import NextAuth, { Session, NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { prismadb } from "@/lib/db";
import { JWT } from "next-auth/jwt";

interface CustomUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
}

interface CustomSession extends Session {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    token: JWT;
  }
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
        async session({ session, token }: { session: Session; token: JWT }) {
            if (session?.user) {
                (session.user as any).id = token.id;
                (session.user as any).firstName = token.firstName || "";
                (session.user as any).lastName = token.lastName || "";
                (session.user as any).token = token;
            }
            return session;
        }
    },
    pages:{
        signIn:"/login",
    },
    session:{ strategy: "jwt" },
    secret:process.env.NEXTAUTH_SECRET,

}

export default NextAuth(authOptions);