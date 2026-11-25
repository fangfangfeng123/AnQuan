import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export const http = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
});

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('sec_auth_token');
  if (token) {
    config.headers['X-API-Token'] = token;
  }
  return config;
});

http.interceptors.response.use(
  (res) => res,
  (err) => {
    const msg = err.response?.data?.message || err.message || '请求失败';
    return Promise.reject(new Error(msg));
  }
);
