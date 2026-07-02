"""Ollama 연결 및 분류 동작 테스트"""
from openai import OpenAI

c = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

# 모델 목록 확인
models = [m.id for m in c.models.list().data]
print("사용 가능한 모델:", models)

# 간단한 응답 테스트
r = c.chat.completions.create(
    model="qwen2.5:7b",
    messages=[{"role": "user", "content": "안녕하세요. 한 문장으로 답해주세요."}],
    max_tokens=100,
    temperature=0,
)
print("응답:", r.choices[0].message.content)
