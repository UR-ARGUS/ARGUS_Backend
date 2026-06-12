from fastapi import APIRouter

router = APIRouter()

@router.post("/")
def trigger_scan():
    return {"message": "Scan triggered successfully"}
