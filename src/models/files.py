from pydantic import BaseModel, Field
from typing import List, Optional


class FileInfo(BaseModel):
    name: str = Field(..., description="File name")
    path: str = Field(..., description="Full path to file")
    size: Optional[int] = Field(None, description="Size in bytes")
    is_dir: bool = Field(False, description="Is a directory")


class DirectoryListing(BaseModel):
    path: str = Field(..., description="Directory path")
    files: List[FileInfo] = Field(default_factory=list)
    directories: List[str] = Field(default_factory=list)
