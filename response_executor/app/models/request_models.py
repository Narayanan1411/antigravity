from pydantic import BaseModel
from typing import Optional


class ExecuteRequest(BaseModel):

    action: str

    target_id: str

    destination_ip: Optional[str] = None

    metadata: Optional[dict] = {}