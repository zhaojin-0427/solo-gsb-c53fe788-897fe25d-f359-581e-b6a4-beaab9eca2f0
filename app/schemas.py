"""请求/响应模型。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, conint

Direction = Literal["c2s", "s2c"]


class CreateSessionRequest(BaseModel):
    session_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="可选；不提供则服务器生成",
    )


class SessionResponse(BaseModel):
    session_id: str
    created: bool


class PacketIn(BaseModel):
    capture: int = Field(ge=0, description="捕获序号（本方向内唯一，越小越早捕获）")
    seq: int = Field(ge=0, le=0xFFFFFFFF, description="32 位 TCP 序列号")
    syn: bool = False
    fin: bool = False
    payload: str = Field(default="", description="Base64 编码的载荷（可为空字符串）")


class UploadRequest(BaseModel):
    packets: list[PacketIn] = Field(min_length=1, max_length=20000)


class PublishRequest(BaseModel):
    expected_revision: int = Field(
        default=0, ge=0, description="期望的当前修订号；首次发布为 0"
    )


class PublishResponse(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    current_revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    run_count: int
    gaps: list[list[int]]


class RevisionMeta(BaseModel):
    revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    run_count: int
    gaps: list[list[int]]
    created_at: str


class DirectionState(BaseModel):
    direction: Direction
    current_revision: int
    packet_count: int
    syn_count: int
    fin: bool


class RunView(BaseModel):
    index: int
    start: int
    end: int
    earliest_source: dict
    latest_source: dict
    divergent: bool


class ReportPage(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    isn: int
    fin_pos: int | None
    complete: bool
    page: dict
    earliest_base64: str
    latest_base64: str
    runs: list[RunView]
    gaps: list[list[int]]
    divergence_intervals: list[list[int]]


# ---- 字节特征定位 ----


class SignatureSearchRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    direction: Direction
    revision: int = Field(
        ge=1,
        description="具体修订号（按会话/方向独立编号，从 1 开始；不支持 latest）",
    )
    pattern_base64: str = Field(
        description="非空字节模式的标准 Base64 编码（空串/解码为空均返回 422）"
    )
    offset: int = Field(default=1, ge=1, le=1 << 31, description="分页起点（逻辑偏移）")
    limit: int = Field(
        default=100, ge=1, le=10000, description="正整数页大小（返回命中条数上限）"
    )


class SignatureHit(BaseModel):
    offset: int = Field(description="命中起点逻辑偏移（1 基）")
    length: int
    category: Literal["both", "earliest_only", "latest_only"]


class SignatureSearchPage(BaseModel):
    session_id: str
    direction: Direction
    revision: int
    pattern_base64: str
    page: dict
    hits: list[SignatureHit]
