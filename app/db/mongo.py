from typing import Optional

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from app.config import db_settings


class MongoSession:
    client: Optional[AsyncMongoClient] = None


mongo_session = MongoSession()


async def connect_to_mongo() -> None:
    mongo_session.client = AsyncMongoClient(db_settings.MONGO_URI)
    print("Connected to MongoDB")


async def close_mongo_connection() -> None:
    if mongo_session.client:
        await mongo_session.client.close()
        print("MongoDB connection closed")


def get_mongo_db() -> AsyncDatabase:
    if not mongo_session.client:
        raise RuntimeError("MongoDB client not initialized")
    return mongo_session.client[db_settings.MONGO_DB_NAME]
