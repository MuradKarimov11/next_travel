import NextAuth, { Session, NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { prismadb } from "@/lib/db";
import { JWT } from "next-auth/jwt";

interface CustomToken extends JWT {
  id?: string;
  firstName?: string;
  lastName?: string;
}

interface CustomUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
}

interface CustomSessionUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  token: CustomToken;
}

interface CustomSession extends Session {
  user: CustomSessionUser;
}

export const authOptions: NextAuthOptions={
    providers:[
        CredentialsProvider({
            name:"Credentials",
            credentials:{
                email: {label:"Email", type:"text"},
                password: { label: "Password", type: "password" },
            },
            async authorize(credentials){
                if (!credentials?.email || !credentials?.password) {
                    throw new Error("Missing email or password");
                }

                const user = await prismadb.user.findUnique({ where: { email: credentials.email } });

                if (!user) {
                    throw new Error("No user found with this email.");
                }

                const isPasswordValid = await bcrypt.compare(credentials.password, user.hashedPassword);

                if (!isPasswordValid) {
                    throw new Error("Incorrect password.");
                }

                return {
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName,
                    lastName: user.lastName,
                };
            }
        })
    ],
    callbacks:{
        async jwt({token, user}){
            if(user){
                const customUser = user as CustomUser;
                token.id = customUser.id;
                token.firstName = customUser.firstName;
                token.lastName = customUser.lastName;
            }
            return token;
        },
        async session({ session, token }: { session: Session; token: CustomToken }): Promise<CustomSession> {
            if (session.user) {
                const customUser: CustomSessionUser = {
                id: token.id ?? "",
                email: session.user.email ?? "",
                firstName: token.firstName ?? "",
                lastName: token.lastName ?? "",
                token,
                };
                return { ...session, user: customUser };
            }
            return session as CustomSession;
        }
    },
    pages:{
        signIn:"/login",
    },
    session:{ strategy: "jwt" },
    secret:process.env.NEXTAUTH_SECRET,

}

export default NextAuth(authOptions);