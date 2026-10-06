"""字节特征定位：在指定修订的 earliest / latest 两份字节流上扫描字节模式。

匹配语义（与发布/报告模型一致）：

* 修订不可变：run 只保存逻辑区间与来源报文引用，本模块在扫描时才经
  ``db.payload_slices`` 还原两份字节流；晚到报文发布新修订不影响旧修订。
* **允许重叠命中**：KMP 完整匹配一次后沿 failure 边回退，而非跳过整段模式
  （``AA`` 在 ``AAA`` 中命中偏移 1 和 2）。
* **相邻 run 可构成命中**：前一 run 末端 == 下一 run 首端时，KMP 自动机状态
  原样延续，模式可跨 run（可跨多次读取窗口）。
* **缺口必须截断**：相邻 run 之间若有缺失偏移，匹配状态清零，绝不把缺口
  两端的字节拼在一起匹配。
* 命中按逻辑起点排序；同一偏移两侧都命中归并为 ``both``，否则为
  ``earliest_only`` / ``latest_only``。
* 分页无状态：从 ``offset`` 起扫（落在缺口内则跳到下一个有字节的 run）。
  每侧先取至多 ``limit+1`` 个命中；若归并后第 ``limit+1`` 个位置落在取数
  不足的一侧，则抬高该侧取数上限续扫，直到能确定 ``next_offset``。
"""

from __future__ import annotations

import base64

from . import db

DEFAULT_LIMIT = 100
HARD_LIMIT = 10000

# 每次从 SQLite 读取的 run 数（一次“读取窗口”）。模式跨窗口时靠 KMP 状态接续。
_READ_BATCH = 1000


def kmp_failure(pattern: bytes) -> list[int]:
    """构造 KMP failure 数组（部分匹配表）。"""
    fail = [0] * len(pattern)
    k = 0
    for i in range(1, len(pattern)):
        while k and pattern[i] != pattern[k]:
            k = fail[k - 1]
        if pattern[i] == pattern[k]:
            k += 1
        fail[i] = k
    return fail


def _scan_side(
    conn,
    session_id: str,
    direction: str,
    revision: int,
    side: str,
    pattern: bytes,
    offset: int,
    want: int,
) -> list[int]:
    """扫描单侧字节流（earliest / latest），返回至多 ``want`` 个命中起点。

    run 按 idx 分批读取；KMP 自动机状态跨读取窗口保留，遇到缺口清零。
    """
    pid_col = "earliest_packet" if side == "earliest" else "latest_packet"
    fail = kmp_failure(pattern)
    m = len(pattern)

    state = 0  # 当前已匹配的模式前缀长度
    cursor = 0  # 已喂入的最后一个 run 的末端（exclusive），用于判定连续性
    started = False
    hits: list[int] = []
    last_idx = -1

    while True:
        if not started:
            # 首页：只需末端越过 offset 的 run；落在 offset 之前（含恰好在
            # offset 结束）的 run 不可能贡献起点 >= offset 的命中。
            rows = conn.execute(
                f"SELECT idx, start_offset AS s, end_offset AS e,"
                f" {pid_col} AS pid FROM runs"
                " WHERE session_id=? AND direction=? AND revision=?"
                " AND end_offset>? AND idx>? ORDER BY idx LIMIT ?",
                (session_id, direction, revision, offset, last_idx, _READ_BATCH),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT idx, start_offset AS s, end_offset AS e,"
                f" {pid_col} AS pid FROM runs"
                " WHERE session_id=? AND direction=? AND revision=?"
                " AND idx>? ORDER BY idx LIMIT ?",
                (session_id, direction, revision, last_idx, _READ_BATCH),
            ).fetchall()
        if not rows:
            return hits

        refs: list[tuple[int, int, int]] = []
        # (refs 下标, 喂入前是否需清零状态)：缺口在窗口内也要截断
        feed: list[tuple[int, bool]] = []
        reset_before_feed = False
        for r in rows:
            last_idx = r["idx"]
            if not started:
                lo = max(r["s"], offset)  # 从页起点开始喂；KMP 从状态 0 扫后缀
                started = True
            else:
                if r["s"] > cursor:
                    # 中间有缺口：标记喂入该 run 前截断，绝不拼接缺口两端
                    reset_before_feed = True
                # r["s"] == cursor 即相邻 run：状态保持，允许跨 run 命中
                lo = r["s"]
            if r["e"] > lo:
                refs.append((r["pid"], lo, r["e"]))
                feed.append((len(refs) - 1, reset_before_feed))
            reset_before_feed = False
            cursor = r["e"]

        slices = db.payload_slices(conn, refs) if refs else []

        for ref_k, must_reset in feed:
            if must_reset:
                state = 0
            lo = refs[ref_k][1]
            data = slices[ref_k]
            end_pos = lo - 1
            for ch in data:
                while state and ch != pattern[state]:
                    state = fail[state - 1]
                if ch == pattern[state]:
                    state += 1
                end_pos += 1
                if state == m:
                    hits.append(end_pos - m + 1)  # 命中起点（1 基）
                    if len(hits) >= want:
                        return hits
                    # 回退而非归零：允许重叠命中
                    state = fail[state - 1]

        if len(rows) < _READ_BATCH:
            return hits


def search_page(
    conn,
    session_id: str,
    direction: str,
    revision: int,
    pattern: bytes,
    offset: int,
    limit: int,
) -> dict | None:
    """构建一页字节特征定位结果；修订不存在返回 None。"""
    meta = db.get_revision_meta(conn, session_id, direction, revision)
    if meta is None:
        return None

    # 两侧各自的取数上限（命中数）；初始 limit+1。截顶（返回数==want）意味着
    # 后面可能还有命中，归并到边界时需要抬高上限续扫。
    want_e = want_l = limit + 1
    while True:
        e_hits = _scan_side(
            conn, session_id, direction, revision, "earliest",
            pattern, offset, want_e,
        )
        l_hits = _scan_side(
            conn, session_id, direction, revision, "latest",
            pattern, offset, want_l,
        )
        e_capped = len(e_hits) == want_e
        l_capped = len(l_hits) == want_l

        merged: list[dict] = []
        i = j = 0
        short_side: str | None = None
        while len(merged) <= limit:
            if i < len(e_hits) and j < len(l_hits):
                if e_hits[i] < l_hits[j]:
                    merged.append({"offset": e_hits[i], "category": "earliest_only"})
                    i += 1
                elif l_hits[j] < e_hits[i]:
                    merged.append({"offset": l_hits[j], "category": "latest_only"})
                    j += 1
                else:
                    merged.append({"offset": e_hits[i], "category": "both"})
                    i += 1
                    j += 1
            elif i < len(e_hits):
                merged.append({"offset": e_hits[i], "category": "earliest_only"})
                i += 1
            elif j < len(l_hits):
                merged.append({"offset": l_hits[j], "category": "latest_only"})
                j += 1
            else:
                break  # 两侧真实耗尽

            if len(merged) > limit:
                last = merged[-1]
                # 第 limit+1 条若仅属一侧，另一侧必须能确认不存在 <= 该点的命中
                if last["category"] == "earliest_only" and l_capped:
                    short_side = "latest"
                elif last["category"] == "latest_only" and e_capped:
                    short_side = "earliest"

        if short_side == "latest":
            want_l = max(want_l * 2, want_l + 1)
            continue
        if short_side == "earliest":
            want_e = max(want_e * 2, want_e + 1)
            continue
        break

    page_hits = merged[:limit]
    next_offset = merged[limit]["offset"] if len(merged) > limit else None
    length = len(pattern)

    return {
        "session_id": session_id,
        "direction": direction,
        "revision": meta["revision"],
        "pattern_base64": base64.b64encode(pattern).decode("ascii"),
        "page": {
            "offset": offset,
            "limit": limit,
            "returned": len(page_hits),
            "next_offset": next_offset,
            "done": next_offset is None,
        },
        "hits": [
            {"offset": h["offset"], "length": length, "category": h["category"]}
            for h in page_hits
        ],
    }
