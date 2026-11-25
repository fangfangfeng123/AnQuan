import { create } from 'zustand';
import { getMe, login, type AuthUser } from '../api/auth';

interface AuthState {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  loadFromStorage: () => Promise<void>;
  logout: () => void;
  can: (permission: string) => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  loading: false,

  login: async (username, password) => {
    const result = await login(username, password);
    localStorage.setItem('sec_auth_token', result.token);
    set({
      user: {
        username: result.username,
        role: result.role,
        display_name: result.display_name,
        permissions: result.permissions,
      },
    });
  },

  loadFromStorage: async () => {
    const token = localStorage.getItem('sec_auth_token');
    if (!token) {
      set({ user: null, loading: false });
      return;
    }
    set({ loading: true });
    try {
      const me = await getMe();
      const permissions =
        me.role === 'admin'
          ? [
              'project:create',
              'project:delete',
              'task:create',
              'task:delete',
              'report:delete',
              'audit:manage',
              'config:manage',
            ]
          : me.role === 'security_auditor'
          ? ['project:create', 'task:create', 'report:export', 'evidence:view']
          : ['project:view', 'finding:view', 'patch:adopt'];
      set({
        user: {
          username: me.username,
          role: me.role,
          display_name:
            me.display_name ||
            (me.role === 'admin' ? '系统管理员' : me.username),
          permissions,
        },
        loading: false,
      });
    } catch {
      localStorage.removeItem('sec_auth_token');
      set({ user: null, loading: false });
    }
  },

  logout: () => {
    localStorage.removeItem('sec_auth_token');
    set({ user: null });
  },

  can: (permission) => {
    const user = get().user;
    return user?.permissions?.includes(permission) ?? false;
  },
}));
