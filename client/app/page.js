"use client";

import { Button } from "@material-tailwind/react";
import { client } from "@passwordless-id/webauthn";
import axios from "axios";

export default function Home() {
  const getChallenge = async () => {
    const res = await axios.get(
      "http://localhost:8080/api/generate/passkey/challenge"
    );

    if (!res.data.success) return console.error(res.data.error);

    return res.data.challenge;
  };

  const register = async () => {
    const challenge = await getChallenge();

    const registration = await client.register("Fusion", challenge, {
      authenticatorType: "auto",
      userVerification: "required",
      timeout: 60000,
      debug: false,
    });

    console.log(registration);

    const res = await axios.post(
      "http://localhost:8080/api/generate/passkey/add",
      { registration, challenge }
    );

    if (!res.data.success) return console.error(res.data.error);

    console.log(res.data);
  };

  const authenticate = async () => {
    const challenge = await getChallenge();

    const authentication = await client.authenticate([], challenge, {
      authenticatorType: "auto",
      userVerification: "required",
      timeout: 60000,
    });

    console.log(authentication);

    const res = await axios.post(
      "http://localhost:8080/api/generate/passkey/authenticate",
      { authentication, challenge }
    );

    if (!res.data.success) return console.error(res.data.error);

    console.log(res.data);
  };

  return (
    <main className="p-10">
      <Button onClick={register}>WebAuthn Authorization</Button>
      <Button onClick={authenticate}>WebAuthn Authentication</Button>
    </main>
  );
}
