from pydantic import BaseModel, EmailStr, Field

class UserSchema(BaseModel):
    full_name: str = Field(max_length=50)
    email: EmailStr = Field(max_length=50)