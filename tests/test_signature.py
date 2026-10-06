"""字节特征定位测试：跨 run 命中、双侧类别、重叠命中、缺口截断、分页、状态码。"""

import base64
import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "api.db")
    monkeypatch.setenv("DB_PATH", db_path)
    from app import main

    importlib.reload(main)
    main.DB_PATH = db_path
    with TestClient(main.app) as c:
        yield c


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


SEARCH = "/sessions/x/directions/c2s/signature-search"


def search(client, pattern, **kw):
    body = {
        "session_id": "x",
        "direction": "c2s",
        "revision": kw.pop("revision", 1),
        "pattern_base64": b64(pattern),
    }
    body.update(kw)
    return client.post(SEARCH, json=body)


def test_cross_run_hit_adjacent_runs(client):
    # 单个报文连续字节 ABCDEFGH，模式 HELL? 用更简单的 DEFG 跨 run 不好切：
    # 构造两个不同来源的相邻 run（capture 边界），模式跨在边界上。
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 10, "seq": 1, "payload": b64(b"ABCDEFGH")},
        {"capture": 20, "seq": 1, "payload": b64(b"A")},  # 覆盖偏移1 => 两个 run
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    # run0=[1,2) earliest=latest=capture20 "A"; run1=[2,9) capture10 "BCDEFGH"
    # 模式 AB 横跨 run 边界（偏移1..2）
    r = search(client, b"AB")
    assert r.status_code == 200
    j = r.json()
    assert j["hits"] == [
        {"offset": 1, "length": 2, "category": "both"},
    ]
    assert j["page"]["next_offset"] is None and j["page"]["done"] is True


def test_cross_read_boundary_match_state(monkeypatch):
    # 读取窗口缩到 2 个 run/批：跨多个读取窗口的命中状态必须接续。
    from app import signature
    monkeypatch.setattr(signature, "_READ_BATCH", 2)

    import tempfile
    from app import db

    path = tempfile.mkdtemp()
    conn = db.connect(path + "/t.db")
    db.init_db(conn)
    db.create_session(conn, "y")
    # capture30 覆盖 [4,6) DE，制造 4 个相邻 run，模式 CDEFG 跨 3 个 run。
    isn = 0
    db.add_packets(conn, "y", "c2s", [
        (1, isn, 1, 0, b""),
        (10, isn + 1, 0, 0, b"ABCDEFGH"),
        (20, isn + 1, 0, 0, b"A"),    # run [1,2)
        (30, isn + 4, 0, 0, b"DE"),   # run [4,6) 翻转
    ])
    # runs: [1,2) A(20); [2,4) BC(10); [4,6) DE(30); [6,9) FGH(10)
    db.publish_revision(conn, "y", "c2s", 0)
    page = signature.search_page(conn, "y", "c2s", 1, b"CDEFG", 1, 100)
    # CDE 横跨 run[2,4)/run[4,6)，FG 再接 run[6,9)：命中偏移 3
    assert page is not None
    assert page["hits"] == [
        {"offset": 3, "length": 5, "category": "both"},
    ]


def test_categories_both_earliest_only_latest_only(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 10, "seq": 1, "payload": b64(b"HELLO")},
        {"capture": 20, "seq": 1, "payload": b64(b"JELLO")},  # 仅首字节分歧
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    # earliest=HELLO, latest=JELLO
    r = search(client, b"HELLO")
    assert r.json()["hits"] == [
        {"offset": 1, "length": 5, "category": "earliest_only"}
    ]
    r = search(client, b"JELLO")
    assert r.json()["hits"] == [
        {"offset": 1, "length": 5, "category": "latest_only"}
    ]
    # ELLO 两份流从偏移 2 起完全一致 -> both
    r = search(client, b"ELLO")
    assert r.json()["hits"] == [
        {"offset": 2, "length": 4, "category": "both"}
    ]


def test_overlapping_hits_allowed(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AAA")},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    r = search(client, b"AA")
    assert [h["offset"] for h in r.json()["hits"]] == [1, 2]
    assert all(h["category"] == "both" for h in r.json()["hits"])


def test_gap_truncates_match(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},    # [1,3)
        {"capture": 3, "seq": 10, "payload": b64(b"CD")},   # [10,12)
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    # 单字节命中正常
    assert [h["offset"] for h in search(client, b"C").json()["hits"]] == [10]
    # 跨缺口的拼接模式 BC 绝不命中
    assert search(client, b"BC").json()["hits"] == []
    # 页起点落在缺口内：跳到下一个 run
    j = search(client, b"CD", offset=5).json()
    assert [h["offset"] for h in j["hits"]] == [10]


def test_pagination_next_offset(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AAAAA")},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    # AA 在 1..4 四个重叠命中
    p1 = search(client, b"AA", limit=2).json()
    assert [h["offset"] for h in p1["hits"]] == [1, 2]
    assert p1["page"]["next_offset"] == 3 and p1["page"]["done"] is False

    p2 = search(client, b"AA", offset=p1["page"]["next_offset"], limit=2).json()
    assert [h["offset"] for h in p2["hits"]] == [3, 4]
    assert p2["page"]["next_offset"] is None and p2["page"]["done"] is True

    # 末页之后再来一页为空页
    p3 = search(client, b"AA", offset=5).json()
    assert p3["hits"] == [] and p3["page"]["next_offset"] is None


def test_empty_page_when_no_hit(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    r = search(client, b"ZZ")
    assert r.status_code == 200
    j = r.json()
    assert j["hits"] == []
    assert j["page"] == {
        "offset": 1, "limit": 100, "returned": 0,
        "next_offset": None, "done": True,
    }


def test_error_codes(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 2, "seq": 1, "payload": b64(b"AB")},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})

    # 非法 Base64 -> 422
    r = client.post(SEARCH, json={
        "session_id": "x", "direction": "c2s", "revision": 1,
        "pattern_base64": "@@bad@@",
    })
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_base64"

    # 空模式（合法 Base64 解码为空）-> 422
    r = client.post(SEARCH, json={
        "session_id": "x", "direction": "c2s", "revision": 1,
        "pattern_base64": "",
    })
    assert r.status_code == 422

    # limit 非正整数 -> 422（pydantic 校验）
    r = client.post(SEARCH, json={
        "session_id": "x", "direction": "c2s", "revision": 1,
        "pattern_base64": b64(b"A"), "limit": 0,
    })
    assert r.status_code == 422

    # 未知修订 -> 404
    r = search(client, b"A", revision=99)
    assert r.status_code == 404

    # 未知会话 -> 404
    r = client.post(
        "/sessions/nope/directions/c2s/signature-search",
        json={"session_id": "nope", "direction": "c2s",
              "revision": 1, "pattern_base64": b64(b"A")},
    )
    assert r.status_code == 404


def test_old_revision_hits_immutable_after_late_packet(client):
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 20, "seq": 1, "payload": b64(b"AB")},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})  # rev1: AB
    # 晚到但 capture 更小的报文翻转 earliest
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 10, "seq": 1, "payload": b64(b"xC")},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 1})  # rev2

    # 旧修订命中不变：AB 在 rev1 仍 both 命中
    old = search(client, b"AB", revision=1).json()
    assert [h["offset"] for h in old["hits"]] == [1]
    assert old["hits"][0]["category"] == "both"
    # 新修订：earliest=xC, latest=AB
    new = search(client, b"AB", revision=2).json()
    assert new["hits"] == [
        {"offset": 1, "length": 2, "category": "latest_only"}
    ]
    assert search(client, b"xC", revision=2).json()["hits"][0]["category"] == "earliest_only"


def test_pagination_rescan_when_pivot_side_capped(client):
    # earliest = A*20（AA 密集命中 1..19），latest = A + B*19（仅偏移1有 A）。
    # 模式 B 只在 latest 命中（2..20），earliest 扫描在 limit+1 处截顶于 AA，
    # 归并的第 limit+1 条是 latest_only：必须续扫 earliest 全流确认无 B，
    # next_offset 仍由 latest 第 limit+1 条决定。
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 0, "syn": True},
        {"capture": 10, "seq": 1, "payload": b64(b"A" * 20)},
        {"capture": 20, "seq": 1, "payload": b64(b"A" + b"B" * 19)},
    ]})
    client.post("/sessions/x/directions/c2s/revisions",
                json={"expected_revision": 0})
    r = search(client, b"B", limit=3)
    assert r.status_code == 200
    j = r.json()
    assert [(h["offset"], h["category"]) for h in j["hits"]] == [
        (2, "latest_only"), (3, "latest_only"), (4, "latest_only"),
    ]
    assert j["page"]["next_offset"] == 5 and j["page"]["done"] is False

    # A 两侧都有：offset1 both，其余 earliest_only
    j = search(client, b"A", limit=3).json()
    assert [(h["offset"], h["category"]) for h in j["hits"]] == [
        (1, "both"), (2, "earliest_only"), (3, "earliest_only"),
    ]


def test_existing_publish_and_report_still_work(client):
    # 回归：原发布/报告链路
    client.post("/sessions", json={"session_id": "x"})
    client.post("/sessions/x/directions/c2s/packets", json={"packets": [
        {"capture": 1, "seq": 1000, "syn": True},
        {"capture": 2, "seq": 1001, "payload": b64(b"AB")},
        {"capture": 3, "seq": 1003, "fin": True},
    ]})
    r = client.post("/sessions/x/directions/c2s/revisions",
                    json={"expected_revision": 0})
    assert r.status_code == 201
    rep = client.get("/sessions/x/directions/c2s/revisions/1/report").json()
    assert rep["earliest_base64"] == b64(b"AB")
    assert rep["complete"] is True
