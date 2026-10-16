from pydantic import BaseModel


class ConsentClient(BaseModel):
    client_id: str
    name: str


class ConsentUser(BaseModel):
    email: str


class ConsentDetailsResponse(BaseModel):
    client: ConsentClient
    scopes: list[str]
    user: ConsentUser


class ConsentDecisionRequest(BaseModel):
    approve: bool


class ConsentDecisionResponse(BaseModel):
    redirect_to: str
