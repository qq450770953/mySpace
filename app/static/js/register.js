document.getElementById('registerForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    
    // 隐藏之前的错误消息
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.style.display = 'none';
    }
    
    // 验证密码匹配
    if (password !== confirmPassword) {
        if (errorMessage) {
            errorMessage.textContent = '两次输入的密码不一致';
            errorMessage.style.display = 'block';
        }
        return;
    }
    
    try {
        console.log('Preparing registration request...');
        const requestData = {
            username: username,
            email: email,
            password: password
        };
        console.log('Request data:', requestData);
        
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Registration response:', data);
        
        if (response.ok) {
            console.log('Registration successful, redirecting to login...');
            window.location.href = '/auth/login';
        } else {
            console.error('Registration failed:', data);
            if (errorMessage) {
                errorMessage.textContent = data.message || data.error || '注册失败，请重试';
                errorMessage.style.display = 'block';
            }
        }
    } catch (error) {
        console.error('Registration error:', error);
        if (errorMessage) {
            errorMessage.textContent = '注册失败，请重试';
            errorMessage.style.display = 'block';
        }
    }
}); 