import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      // authorize関数を使用して認証ロジックを処理
      async authorize(credentials) {
        // サーバーアクションと同様に、ユーザーがデータベースに存在するかどうかを確認する前に、
        // 電子メールとパスワードを検証するためにzodを使用する
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        // 資格情報を検証した後、データベースからユーザーにクエリを実行する新しい関数getUserを作成します。
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;

          // bcrypt.compare呼び出して、パスワードが一致するかどうかを確認
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) return user;
        }
        console.log('Invalid credentials');

        // パスワードが一致する場合はユーザーを返し、ログインを許可します。
        // そうでない場合はnullを返すことでユーザーがログインできないようにします。
        return null;
      },
    }),
  ],
});