// 验证邮箱
function isEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return pattern.test(email);
}

// 验证手机号
function isPhone(phone) {
    const pattern = /^1[3-9]\d{9}$/;
    return pattern.test(phone);
}

// 验证URL
function isUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// 验证身份证号
function isIdCard(idCard) {
    const pattern = /(^\d{15}$)|(^\d{18}$)|(^\d{17}(\d|X|x)$)/;
    return pattern.test(idCard);
}

// 验证密码强度
function checkPasswordStrength(password) {
    let strength = 0;
    
    // 长度检查
    if (password.length >= 8) strength++;
    
    // 包含数字
    if (/\d/.test(password)) strength++;
    
    // 包含小写字母
    if (/[a-z]/.test(password)) strength++;
    
    // 包含大写字母
    if (/[A-Z]/.test(password)) strength++;
    
    // 包含特殊字符
    if (/[!@#$%^&*]/.test(password)) strength++;
    
    return {
        score: strength,
        level: strength < 2 ? '弱' : strength < 4 ? '中' : '强',
        isValid: strength >= 3
    };
}

// 验证是否为空
function isEmpty(value) {
    if (value === null || value === undefined) return true;
    if (typeof value === 'string') return value.trim() === '';
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === 'object') return Object.keys(value).length === 0;
    return false;
}

// 验证数字范围
function isInRange(number, min, max) {
    return number >= min && number <= max;
}

// 验证文件类型
function isValidFileType(file, allowedTypes) {
    return allowedTypes.includes(file.type);
}

// 验证文件大小
function isValidFileSize(file, maxSize) {
    return file.size <= maxSize;
}

// 验证表单
function validateForm(formData, rules) {
    const errors = {};
    
    for (const field in rules) {
        const value = formData[field];
        const fieldRules = rules[field];
        
        for (const rule of fieldRules) {
            if (rule.required && isEmpty(value)) {
                errors[field] = rule.message || '此字段不能为空';
                break;
            }
            
            if (rule.minLength && value.length < rule.minLength) {
                errors[field] = rule.message || `最少需要${rule.minLength}个字符`;
                break;
            }
            
            if (rule.maxLength && value.length > rule.maxLength) {
                errors[field] = rule.message || `最多允许${rule.maxLength}个字符`;
                break;
            }
            
            if (rule.pattern && !rule.pattern.test(value)) {
                errors[field] = rule.message || '格式不正确';
                break;
            }
            
            if (rule.validator && !rule.validator(value)) {
                errors[field] = rule.message || '验证失败';
                break;
            }
        }
    }
    
    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
}

// 导出工具函数
export {
    isEmail,
    isPhone,
    isUrl,
    isIdCard,
    checkPasswordStrength,
    isEmpty,
    isInRange,
    isValidFileType,
    isValidFileSize,
    validateForm
}; 