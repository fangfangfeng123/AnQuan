import { http } from './client';

export interface AuthUser {
  username: string;
  role: string;
  display_name: string;
  permissions: string[];
}

export interface LoginResult extends AuthUser {
  token: string;
}

export async function login(
  username: string,
  password: string
): Promise<LoginResult> {
  const res = await http.post<LoginResult>('/auth/login', {
    username,
    password,
  });
  return res.data;
}

export async function getMe(): Promise<AuthUser> {
  const res = await http.get<AuthUser>('/auth/me');
  return res.data;
}
