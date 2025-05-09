import requests
import os

def test_static_file_access():
    """测试静态文件是否可以被访问"""
    try:
        # 测试基本静态文件
        response = requests.get('http://localhost:5000/static/css/style.css')
        print(f"Style.css: {response.status_code}")
        
        # 测试图片文件
        image_response = requests.get('http://localhost:5000/static/images/background.png')
        print(f"Background image: {image_response.status_code}")
        
        if image_response.status_code == 200:
            print("背景图片可以成功访问！")
            # 保存图片内容到临时文件以验证完整性
            with open('temp_background.png', 'wb') as f:
                f.write(image_response.content)
            
            original_size = os.path.getsize('app/static/images/background.png')
            downloaded_size = os.path.getsize('temp_background.png')
            
            print(f"原始文件大小: {original_size} 字节")
            print(f"下载文件大小: {downloaded_size} 字节")
            
            if original_size == downloaded_size:
                print("文件大小匹配，图片已完整下载")
            else:
                print("警告：文件大小不匹配，可能下载不完整")
        else:
            print(f"无法访问背景图片，状态码: {image_response.status_code}")
            print(f"响应内容: {image_response.text[:200]}...")
    
    except Exception as e:
        print(f"测试过程中出错: {str(e)}")

if __name__ == "__main__":
    test_static_file_access() 