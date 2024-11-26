"""
Endpoints are a direct passthrough to eventrecorder which it can reach through the private network.
Endpoints won't be called if the callee cannot authenticate via this endpoint
"""
import datetime
from typing import Annotated, List

import sentry_sdk
from requests.compat import urljoin
from fastapi import FastAPI, Depends, Request, Response, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
import bcrypt

from eventrecorder_heroku_hook.req_resp_models import RecordReqPayload, RecordResult, BearerToken

from eventrecorder_heroku_hook.environment import Env
env = Env()

# Sentry sdk must be initialized before fastapi is
sentry_sdk.init(
    dsn=env.config.sentry_dsn,
    traces_sample_rate=0.0001,
    profiles_sample_rate=0.0001,
    environment=env.config.mode,
)

app = FastAPI(**env.config.fastapi_app_settings)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_username_from_jwt_token(token: str):
    try:
        payload = jwt.decode(token, env.config.jwt.secret_key, algorithms=[env.config.jwt.algorithm])
        username = payload.get("sub")
    except:
        username = None

    return username

def get_current_user(bearer_token: Annotated[str,Depends(oauth2_scheme)]):
    username = get_username_from_jwt_token(bearer_token)
    user = env.config.authorized_users.get(username)

    if not user:
        print("USER NOT FOUND: ", username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def get_current_active_user(current_user: Annotated[dict, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def authenticate_user(username: str, password: str):
    user = env.config.authorized_users.get(username)

    if user is None:
        return None

    if not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        return None

    return user


def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, env.config.jwt.secret_key, algorithm=env.config.jwt.algorithm)

    return encoded_jwt


@app.post("/token", response_model=BearerToken)
def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    access_token_expires = datetime.timedelta(days=env.config.jwt.expire_days)
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        print("USER NOT FOUND: ", form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return BearerToken(access_token=access_token, token_type="bearer")


@app.get("/health/", tags=["Health Check"], include_in_schema=False)
@app.get("/health", tags=["Health Check"])
def read_health():
    return {"status": "ok"}


@app.post(
    "/record/",
    tags=["Event Recording"],
    response_model=RecordResult,
    include_in_schema=False,
)

@app.post("/record", tags=["Event Recording"], response_model=RecordResult)
async def record_one(record_payload: RecordReqPayload, curr_user: Annotated[dict,Depends(get_current_active_user)], request: Request):
    url = urljoin(env.config.eventrecorder_url, "/record")
    response = await _eventrecorder_request_passthrough(url, request)
    return RecordResult(**response.json())



@app.post(
    "/record/bulk/",
    tags=["Event Recording"],
    response_model=List[RecordResult],
    include_in_schema=False,
)
@app.post("/record/bulk", tags=["Event Recording"], response_model=List[RecordResult])
async def record_many(record_payloads: List[RecordReqPayload], curr_user: Annotated[dict,Depends(get_current_active_user)], request: Request):
    url = urljoin(env.config.eventrecorder_url, "/record/bulk")
    response = await _eventrecorder_request_passthrough(url, request)
    return [RecordResult(**r) for r in response.json()]


async def _eventrecorder_request_passthrough(url: str, request: Request) -> Response:
    response = env.session.post(
        url=url,
        data=await request.body(),
        headers={ "Accept": "application/json", "Content-Type": "application/json" },
    )
    response.raise_for_status()
    return response
