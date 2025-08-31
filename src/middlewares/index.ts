import { geUserBySessionToken } from "db/users.js";
import { get, merge } from "lodash";
import express from "express";

export const isAuthenticated = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  try {
    const sessionToken = req.cookies["AUTH"];
    const existingUser = sessionToken
      ? await geUserBySessionToken(sessionToken)
      : null;

    if (!sessionToken || !existingUser) {
      return res.sendStatus(401);
    }

    merge(req, { identity: existingUser });

    return next();
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Something went wrong" });
  }
};
