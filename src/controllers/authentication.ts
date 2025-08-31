import { createUser, getUserByEmail } from "../db/users.js";
import express from "express";
import { authentication, random } from "../utils/index.js";

export const login = async (req: express.Request, res: express.Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res
        .status(400)
        .json({ message: "Email and Password are required" });
    const user = await getUserByEmail(email).select(
      "+authentication.salt +authentication.password"
    );

    if (!user || !user.authentication?.salt)
      return res.status(401).json({ message: "Email or password incorrect" });

    const expectedHash = authentication(user.authentication.salt, password);

    if (expectedHash !== user.authentication.password)
      return res.status(401).json({ message: "Email or password incorrect" });
    else {
      const salt = random();

      user.authentication.sessionToken = authentication(
        salt,
        user._id.toString()
      );
      await user.save();

      res.cookie("AUTH", user.authentication.sessionToken, {
        domain: "localhost",
        path: "/",
      });
      return res.status(200).json(user).end();
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Something went wrong" });
  }
};

export const register = async (req: express.Request, res: express.Response) => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
      return res.sendStatus(400);
    }

    const existingUser = await getUserByEmail(email);

    if (existingUser) {
      return res.sendStatus(400);
    }

    const salt = random();
    const user = await createUser({
      email,
      username,
      authentication: {
        salt,
        password: authentication(salt, password),
      },
    });

    return res.status(200).json(user).end();
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Something went wrong" });
  }
};
