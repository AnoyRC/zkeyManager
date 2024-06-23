"use client";

import { Button } from "@material-tailwind/react";
import { client } from "@passwordless-id/webauthn";
import axios from "axios";
import { Auth0Client } from "@auth0/auth0-spa-js";

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

    const res = await axios.post("http://localhost:8080/api/utils/pubkey", {
      domain: "anoy.fusion.id",
      authentication,
      challenge,
      payload: "test",
    });

    if (!res.data.success) return console.error(res.data.error);

    console.log(res.data);
  };

  const initiateAuth0 = async () => {
    const auth0 = new Auth0Client({
      domain: "dev-pekknv1gkulrlnlq.us.auth0.com",
      client_id: "HeyxTKrvfv21D5rnCdhSrznnZ6D6rBXQ",
      audience: "https://test.api",
    });

    await auth0.loginWithPopup();

    const user = await auth0.getUser();

    console.log(user);

    const token = await auth0.getTokenSilently();

    console.log(token);

    const res = await axios.get("http://localhost:8080/api/generate/auth0", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!res.data.success) return console.error(res.data.error);

    console.log(res.data);
  };

  const generate = async () => {
    const challenge = await getChallenge();

    const registration = await client.register("Fusion", challenge, {
      authenticatorType: "auto",
      userVerification: "required",
      timeout: 60000,
      debug: false,
    });

    console.log(registration);

    const auth0 = new Auth0Client({
      domain: "dev-pekknv1gkulrlnlq.us.auth0.com",
      client_id: "HeyxTKrvfv21D5rnCdhSrznnZ6D6rBXQ",
      audience: "https://test.api",
    });

    await auth0.loginWithPopup();

    const user = await auth0.getUser();

    console.log(user);

    const token = await auth0.getTokenSilently();

    console.log(token);

    const res = await axios.post(
      "http://localhost:8080/api/generate/",
      {
        domain: "anoy.fusion.id",
        registration,
        challenge,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    if (!res.data.success) return console.error(res.data.error);

    console.log(res.data);
  };

  const recover = async () => {
    const challenge = await getChallenge();

    const registration = await client.register("Fusion", challenge, {
      authenticatorType: "auto",
      userVerification: "required",
      timeout: 60000,
      debug: false,
    });

    console.log(registration);

    const auth0 = new Auth0Client({
      domain: "dev-pekknv1gkulrlnlq.us.auth0.com",
      client_id: "HeyxTKrvfv21D5rnCdhSrznnZ6D6rBXQ",
      audience: "https://test.api",
    });

    await auth0.loginWithPopup();

    const user = await auth0.getUser();

    console.log(user);

    const token = await auth0.getTokenSilently();

    console.log(token);

    const res = await axios.post(
      "http://localhost:8080/api/recover/",
      {
        domain: "anoy.fusion.id",
        registration,
        challenge,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    if (!res.data.success) return console.error(res.data.error);

    console.log(res.data);
  };

  return (
    <main className="p-10">
      <Button onClick={register}>WebAuthn Authorization</Button>
      <Button onClick={authenticate}>WebAuthn Authentication</Button>
      <Button onClick={initiateAuth0}>Auth0</Button>
      <Button onClick={generate}>Full Generation</Button>
      <Button onClick={recover}>Full Recovery</Button>
    </main>
  );
}
