import datetime
from typing import Union
from pydantic import BaseModel


class RecordReqPayload(BaseModel):
    occurred_at: datetime.datetime
    data: dict
    source: str
    version: str
    type: str
    id: Union[int, str] = None
    emitted_at: datetime.datetime = None
    user_name: str = None
    context: dict = None

class RecordResult(BaseModel):
    assigned_id: Union[int, str]
    recorded: bool

class BearerToken(BaseModel):
    access_token: str
    token_type: str
