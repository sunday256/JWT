import base64
import json
from typing import Dict, Tuple

def decode_jwt(token: str) -> Tuple[Dict, Dict, str]:
    """
    解码JWT令牌
    
    Args:
        token: JWT字符串
        
    Returns:
        (header字典, payload字典, 签名字符串)
        
    Raises:
        ValueError: 如果JWT格式无效
    """
    try:
        # 分割三部分
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("JWT格式错误：必须包含 header.payload.signature 三部分")
        
        # Base64Url解码函数
        def base64url_decode(data: str) -> bytes:
            # 添加必要的填充
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            # Base64Url -> Base64
            data = data.replace('-', '+').replace('_', '/')
            return base64.b64decode(data)
        
        # 解码头部和载荷
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
        
        return header, payload, parts[2]
    
    except Exception as e:
        raise ValueError(f"JWT解码失败: {e}")

# 测试一下
if __name__ == "__main__":
    # 一个测试用的JWT
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    try:
        h, p, s = decode_jwt(test_token)
        print("✅ 解码成功！")
        print("头部:", json.dumps(h, indent=2))
        print("载荷:", json.dumps(p, indent=2))
        print("签名:", s[:20] + "...")
    except ValueError as e:
        print("❌ 解码失败:", e)