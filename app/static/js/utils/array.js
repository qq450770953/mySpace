// 数组去重
function unique(arr) {
    return [...new Set(arr)];
}

// 数组分组
function groupBy(arr, key) {
    return arr.reduce((groups, item) => {
        const group = groups[item[key]] || [];
        group.push(item);
        groups[item[key]] = group;
        return groups;
    }, {});
}

// 数组排序
function sortBy(arr, key, order = 'asc') {
    return [...arr].sort((a, b) => {
        const valueA = typeof a[key] === 'string' ? a[key].toLowerCase() : a[key];
        const valueB = typeof b[key] === 'string' ? b[key].toLowerCase() : b[key];
        
        if (order === 'asc') {
            return valueA > valueB ? 1 : -1;
        } else {
            return valueA < valueB ? 1 : -1;
        }
    });
}

// 数组求和
function sum(arr) {
    return arr.reduce((total, current) => total + current, 0);
}

// 数组平均值
function average(arr) {
    if (arr.length === 0) return 0;
    return sum(arr) / arr.length;
}

// 数组最大值
function max(arr) {
    return Math.max(...arr);
}

// 数组最小值
function min(arr) {
    return Math.min(...arr);
}

// 数组交集
function intersection(arr1, arr2) {
    return arr1.filter(item => arr2.includes(item));
}

// 数组并集
function union(arr1, arr2) {
    return unique([...arr1, ...arr2]);
}

// 数组差集
function difference(arr1, arr2) {
    return arr1.filter(item => !arr2.includes(item));
}

// 数组分块
function chunk(arr, size) {
    const chunks = [];
    for (let i = 0; i < arr.length; i += size) {
        chunks.push(arr.slice(i, i + size));
    }
    return chunks;
}

// 导出工具函数
export {
    unique,
    groupBy,
    sortBy,
    sum,
    average,
    max,
    min,
    intersection,
    union,
    difference,
    chunk
}; 