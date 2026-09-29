import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import path from "node:path";
import fs from "node:fs/promises";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  initializeApp,
  applicationDefault,
  cert
} from "firebase-admin/app";

import {
  getFirestore,
  Timestamp
} from "firebase-admin/firestore";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);

const GEMINI_API_KEY =
  String(process.env.GEMINI_API_KEY || "").trim();

const GEMINI_MODEL =
  process.env.GEMINI_MODEL ||
  "gemini-3.8-flash";

const GEMINI_FALLBACK_MODELS = [
  "gemini-3.7-flash",
  "gemini-3.6-flash"
];

const GEMINI_TTS_MODEL =
  process.env.GEMINI_TTS_MODEL ||
  "gemini-3.8-flash-lite-tts";

const FIREBASE_PROJECT_ID =
  String(
    process.env.FIREBASE_PROJECT_ID ||
      "smart-farming-advisory-a5d14"
  ).trim();

const USERS_FILE =
  path.join(__dirname, "users.json");

const app = express();

app.use(
  express.json({
    limit: "15mb"
  })
);

app.use(
  express.static(__dirname)
);

/* =========================================================
   FIREBASE / FIRESTORE
   ========================================================= */

let firestore = null;
let firebaseConfigured = false;

function initializeFirebase() {
  try {
    /*
      Option 1:
      If GOOGLE_APPLICATION_CREDENTIALS is configured,
      Firebase Admin will use the service-account JSON file.
    */

    if (
      process.env.GOOGLE_APPLICATION_CREDENTIALS
    ) {
      initializeApp({
        credential:
          applicationDefault(),
        projectId:
          FIREBASE_PROJECT_ID
      });

      firestore = getFirestore();

      firebaseConfigured = true;

      console.log(
        "🔥 Firebase Firestore: configured"
      );

      return;
    }

    /*
      Option 2:
      Service-account information can be supplied
      through environment variables.

      Required:
      FIREBASE_CLIENT_EMAIL
      FIREBASE_PRIVATE_KEY
    */

    const clientEmail =
      String(
        process.env.FIREBASE_CLIENT_EMAIL || ""
      ).trim();

    const privateKey =
      String(
        process.env.FIREBASE_PRIVATE_KEY || ""
      ).replace(/\\n/g, "\n");

    if (
      clientEmail &&
      privateKey
    ) {
      initializeApp({
        credential: cert({
          projectId:
            FIREBASE_PROJECT_ID,

          clientEmail,

          privateKey
        })
      });

      firestore = getFirestore();

      firebaseConfigured = true;

      console.log(
        "🔥 Firebase Firestore: configured"
      );

      return;
    }

    console.warn(
      "⚠️ Firebase Firestore is not configured yet."
    );

    console.warn(
      "Add Firebase server credentials to .env."
    );

  } catch (error) {
    firebaseConfigured = false;
    firestore = null;

    console.error(
      "🔥 Firebase initialization error:",
      error.message
    );
  }
}

initializeFirebase();

/* =========================================================
   LANGUAGES
   ========================================================= */

const languages = {
  "en-IN": "English",
  "hi-IN": "Hindi",
  "mr-IN": "Marathi",
  "gu-IN": "Gujarati",
  "bn-IN": "Bengali",
  "ta-IN": "Tamil",
  "te-IN": "Telugu",
  "kn-IN": "Kannada",
  "ml-IN": "Malayalam",
  "pa-IN": "Punjabi",
  "ur-IN": "Urdu"
};

/* =========================================================
   AUTH / OTP
   ========================================================= */

const otpStore = new Map();
const tokenStore = new Map();

/* =========================================================
   LOCAL USERS FILE
   ========================================================= */

async function readUsers() {
  try {
    const raw =
      await fs.readFile(
        USERS_FILE,
        "utf8"
      );

    const users =
      JSON.parse(raw);

    return Array.isArray(users)
      ? users
      : [];

  } catch {
    return [];
  }
}

async function writeUsers(users) {
  await fs.writeFile(
    USERS_FILE,
    JSON.stringify(
      users,
      null,
      2
    ),
    "utf8"
  );
}

/* =========================================================
   HELPERS
   ========================================================= */

function clean(
  value,
  fallback = ""
) {
  if (
    value === null ||
    value === undefined
  ) {
    return fallback;
  }

  if (
    typeof value === "object"
  ) {
    value =
      value.name ??
      value.label ??
      value.value ??
      "";
  }

  const text =
    String(value).trim();

  return text || fallback;
}

function normalizeEmail(value) {
  return clean(
    value
  ).toLowerCase();
}

function normalizePhone(value) {
  return clean(value)
    .replace(
      /[^0-9+]/g,
      ""
    );
}

function publicUser(user) {
  return {
    id:
      user.id || "",

    name:
      user.name || "",

    email:
      user.email || "",

    phone:
      user.phone || "",

    location:
      user.location || "",

    crop:
      user.crop || "",

    soil:
      user.soil || "",

    irrigation:
      user.irrigation || "",

    weather:
      user.weather || ""
  };
}

function hashPassword(
  password
) {
  const salt =
    crypto
      .randomBytes(16)
      .toString("hex");

  const hash =
    crypto
      .scryptSync(
        password,
        salt,
        64
      )
      .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  stored
) {
  const [
    salt,
    original
  ] =
    String(
      stored || ""
    ).split(":");

  if (
    !salt ||
    !original
  ) {
    return false;
  }

  const hash =
    crypto
      .scryptSync(
        password,
        salt,
        64
      )
      .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(
      hash,
      "hex"
    ),
    Buffer.from(
      original,
      "hex"
    )
  );
}

function createToken(user) {
  const token =
    crypto
      .randomBytes(32)
      .toString("hex");

  tokenStore.set(
    token,
    user.email
  );

  return token;
}

function requireGemini(res) {
  if (
    !GEMINI_API_KEY
  ) {
    res.status(500).json({
      success: false,
      error:
        "GEMINI_API_KEY is missing in .env."
    });

    return false;
  }

  return true;
}

function requireFirebase(res) {
  if (
    !firebaseConfigured ||
    !firestore
  ) {
    res.status(500).json({
      success: false,
      error:
        "Firebase Firestore is not configured on the server."
    });

    return false;
  }

  return true;
}

function languageName(code) {
  return (
    languages[code] ||
    "English"
  );
}

/* =========================================================
   FIRESTORE FARMER DOCUMENT
   ========================================================= */

function farmerDocument(
  user
) {
  return {
    farmerId:
      clean(user.id),

    farmerName:
      clean(user.name),

    email:
      normalizeEmail(
        user.email
      ),

    phone:
      normalizePhone(
        user.phone
      ),

    location:
      clean(user.location),

    mainCrop:
      clean(user.crop),

    soilType:
      clean(user.soil),

    irrigationMethod:
      clean(user.irrigation),

    currentWeather:
      clean(user.weather),

    updatedAt:
      Timestamp.now()
  };
}

/* =========================================================
   SAVE FARMER TO FIRESTORE
   ========================================================= */

async function saveFarmerToFirestore(
  user,
  extraData = {}
) {
  if (
    !firebaseConfigured ||
    !firestore
  ) {
    return false;
  }

  const farmerId =
    clean(user?.id);

  if (!farmerId) {
    throw new Error(
      "Farmer ID is missing."
    );
  }

  const data = {
    ...farmerDocument(user),
    ...extraData
  };

  const farmerRef =
    firestore
      .collection("farmers")
      .doc(farmerId);

  await farmerRef.set(
    data,
    {
      merge: true
    }
  );

  return true;
}

/* =========================================================
   READ FARMER FROM FIRESTORE
   ========================================================= */

async function getFarmerFromFirestore(
  farmerId
) {
  if (
    !firebaseConfigured ||
    !firestore ||
    !farmerId
  ) {
    return null;
  }

  const snapshot =
    await firestore
      .collection("farmers")
      .doc(farmerId)
      .get();

  if (
    !snapshot.exists
  ) {
    return null;
  }

  return {
    id:
      snapshot.id,

    ...snapshot.data()
  };
}

/* =========================================================
   FARMING PROMPT
   ========================================================= */

function farmingPrompt(
  body,
  problem,
  mode = "advice"
) {
  const language =
    languageName(
      body.languageCode
    );

  const crop =
    clean(
      body.crop,
      "not specified"
    );

  const soil =
    clean(
      body.soil,
      "not specified"
    );

  const irrigation =
    clean(
      body.irrigation,
      "not specified"
    );

  const weather =
    clean(
      body.weather,
      "not specified"
    );

  const location =
    clean(
      body.location,
      "not specified"
    );

  return `You are a careful agricultural advisor for Indian farmers.

OUTPUT LANGUAGE: ${language}

The website interface is English, but your actual farming answer MUST be entirely in ${language}.

Do not start with a generic greeting unless it is useful.

FARM CONTEXT:

Farmer:
${clean(
  body.name ||
    body.farmerName,
  "Farmer"
)}

Location:
${location}

Main crop:
${crop}

Soil type:
${soil}

Irrigation:
${irrigation}

Current weather supplied by farmer:
${weather}

FARMER'S CURRENT MESSAGE:

${
  problem ||
  "The farmer uploaded a crop photo. Analyze the visible symptoms and explain what should be checked and done."
}

STRICT SAFETY / ADVICE RULE:

- The farmer specifically wants NON-CHEMICAL advice.
- Do NOT recommend pesticides.
- Do NOT recommend insecticides.
- Do NOT recommend fungicides.
- Do NOT recommend herbicides.
- Do NOT recommend chemical sprays.
- Do NOT recommend synthetic fertilizers.
- Do NOT recommend chemical treatment doses.
- Prefer practical cultural, mechanical, physical, sanitation, irrigation-management, biological-control, resistant-variety, pruning, staking, drainage, mulching, compost/organic-matter and monitoring steps where appropriate.
- Never claim a disease is certain from a photo alone.
- Use wording such as "possible" or "likely" when appropriate.
- If the photo is unclear, say exactly what extra photo or observation would help.
- Do not invent weather or location facts that were not supplied.

${
  mode === "chat"
    ? `This is a continuing conversation. Answer the farmer's latest question directly and use the context above.`
    : `Give a focused diagnosis/assessment and practical next steps.`
}

STRUCTURE:

1. Likely issue / observation
2. Why it may be happening
3. What to do now — non-chemical steps only
4. What to monitor over the next few days
5. When to contact a local agriculture officer or agronomist

Keep it practical and specific to the crop and problem.

Avoid generic textbook paragraphs.`;
}

/* =========================================================
   GEMINI RESPONSE
   ========================================================= */

function extractGeminiText(
  data
) {
  const candidates =
    Array.isArray(
      data?.candidates
    )
      ? data.candidates
      : [];

  const parts =
    candidates.flatMap(
      candidate =>
        Array.isArray(
          candidate
            ?.content
            ?.parts
        )
          ? candidate.content.parts
          : []
    );

  return parts
    .map(part =>
      typeof part?.text ===
      "string"
        ? part.text
        : ""
    )
    .join("\n")
    .trim();
}

/* =========================================================
   IMAGE DATA URL
   ========================================================= */

function parseDataUrl(
  dataUrl
) {
  const match =
    String(
      dataUrl || ""
    ).match(
      /^data:(image\/(?:png|jpeg|jpg|webp));base64,(.+)$/i
    );

  if (!match) {
    return null;
  }

  return {
    mimeType:
      match[1]
        .toLowerCase()
        .replace(
          "image/jpg",
          "image/jpeg"
        ),

    data:
      match[2]
  };
}

/* =========================================================
   GEMINI API
   ========================================================= */

async function fetchGeminiWithFallback(requestBody) {
  const models = [
    GEMINI_MODEL,
    ...GEMINI_FALLBACK_MODELS
  ];

  let lastError = null;

  for (const model of models) {
    try {
      console.log("Trying Gemini model: - server.mjs:742", model);

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": GEMINI_API_KEY
          },
          body: JSON.stringify(requestBody)
        }
      );

      if (response.ok) {
        console.log("Gemini model succeeded: - server.mjs:757", model);
        return response;
      }

      const errorText = await response.text();

      console.warn(
        `Gemini ${model} failed:`,
        response.status,
        errorText
      );

      lastError = new Error(
        `Gemini ${model} returned HTTP ${response.status}`
      );

      if (![429, 500, 502, 503, 504].includes(response.status)) {
        break;
      }

    } catch (error) {
      console.warn(
        `Gemini ${model} request error:`,
        error.message
      );

      lastError = error;
    }
  }

  throw (
    lastError ||
    new Error("All Gemini models are temporarily unavailable.")
  );
}
async function callGemini({
  prompt,
  imageDataUrl = "",
  contents = null
}) {
  const parts = [];

  if (contents) {
    parts.push(
      ...contents
    );
  } else {
    parts.push({
      text: prompt
    });

    const image =
      parseDataUrl(
        imageDataUrl
      );

    if (image) {
      parts.push({
        inline_data:
          image
      });
    }
  }

  const response =
    await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
        GEMINI_MODEL
      )}:generateContent`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          "x-goog-api-key":
            GEMINI_API_KEY
        },

        body:
          JSON.stringify({
            contents: [
              {
                role: "user",

                parts
              }
            ],

            generationConfig: {
              temperature:
                0.35,

              maxOutputTokens:
                1800
            }
          })
      }
    );

  const raw =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(raw);
  } catch {
    data = {
      error: {
        message: raw
      }
    };
  }

  if (!response.ok) {
    throw new Error(
      data?.error?.message ||
        `Gemini request failed (${response.status}).`
    );
  }

  const text =
    extractGeminiText(
      data
    );

  if (!text) {
    throw new Error(
      "Gemini returned an empty response."
    );
  }

  return text;
}

/* =========================================================
   YOUTUBE LINKS
   ========================================================= */

function buildYouTubeLinks(
  crop,
  problem
) {
  const base =
    `${crop} farming ${problem}`.trim();

  const searches = [
    `${base} India non chemical management`,
    `${crop} disease symptoms natural management India`,
    `${crop} irrigation crop care India farmer`
  ];

  return searches.map(
    (query, index) => ({
      title: [
        `${crop} — problem-focused farming videos`,
        `${crop} — disease and natural management videos`,
        `${crop} — irrigation and crop-care videos`
      ][index],

      url:
        `https://www.youtube.com/results?search_query=${encodeURIComponent(
          query
        )}`
    })
  );
}

/* =========================================================
   WIKIMEDIA FARMING PHOTOS
   ========================================================= */

async function getWikimediaPhotos(
  crop,
  problem
) {
  const query =
    encodeURIComponent(
      `${crop} plant ${problem}`.trim()
    );

  const url =
    `https://commons.wikimedia.org/w/api.php?action=query&generator=search&gsrsearch=${query}&gsrnamespace=6&gsrlimit=3&prop=imageinfo&iiprop=url|extmetadata&iiurlwidth=600&format=json&origin=*`;

  try {
    const response =
      await fetch(url);

    if (!response.ok) {
      return [];
    }

    const data =
      await response.json();

    const pages =
      Object.values(
        data?.query
          ?.pages || {}
      );

    return pages
      .slice(0, 3)
      .map(
        page => ({
          title:
            page.title?.replace(
              /^File:/,
              ""
            ) ||
            "Farming reference photo",

          url:
            page.imageinfo?.[0]
              ?.thumburl ||
            page.imageinfo?.[0]
              ?.url ||
            "",

          pageUrl:
            `https://commons.wikimedia.org/wiki/${encodeURIComponent(
              page.title || ""
            )}`
        })
      )
      .filter(
        item => item.url
      );

  } catch {
    return [];
  }
}

/* =========================================================
   HEALTH
   ========================================================= */

app.get(
  "/api/health",
  (_req, res) => {
    res.json({
      success: true,

      status:
        "running",

      server:
        "Smart Farming Gemini server",

      geminiConfigured:
        Boolean(
          GEMINI_API_KEY
        ),

      geminiModel:
        GEMINI_MODEL,

      ttsModel:
        GEMINI_TTS_MODEL,

      firebaseConfigured:
        firebaseConfigured,

      firebaseProject:
        FIREBASE_PROJECT_ID,

      firestoreCollection:
        "farmers",

      youtubeAPI:
        "NOT USED",

      youtubeMode:
        "Dynamic search links without YouTube API",

      supportedLanguages:
        Object.keys(
          languages
        ),

      endpoints: {
        home: "/",
        advice:
          "/api/farming-advice",
        voice:
          "/api/voice-chat",
        tts:
          "/api/tts",
        resources:
          "/api/resources",
        profile:
          "/api/profile",
        health:
          "/api/health"
      }
    });
  }
);

/* =========================================================
   FARMING ADVICE TEST
   ========================================================= */

app.get(
  "/api/farming-advice",
  (_req, res) => {
    res.json({
      success: true,

      message:
        "Farming advice API is working.",

      method:
        "POST",

      endpoint:
        "/api/farming-advice"
    });
  }
);

/* =========================================================
   REGISTER OTP
   ========================================================= */

app.post(
  "/api/auth/register/request-otp",
  async (req, res) => {
    const phone =
      normalizePhone(
        req.body?.phone
      );

    if (
      !phone ||
      phone.length < 8
    ) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Enter a valid phone number."
        });
    }

    const otp =
      "123456";

    otpStore.set(
      `register:${phone}`,
      {
        otp,

        expires:
          Date.now() +
          5 * 60 * 1000
      }
    );

    res.json({
      success: true,

      message:
        "OTP generated.",

      developmentOtp:
        otp
    });
  }
);

/* =========================================================
   REGISTER VERIFY
   ========================================================= */

app.post(
  "/api/auth/register/verify-otp",
  async (req, res) => {
    const name =
      clean(
        req.body?.name
      );

    const email =
      normalizeEmail(
        req.body?.email
      );

    const password =
      clean(
        req.body?.password
      );

    const phone =
      normalizePhone(
        req.body?.phone
      );

    const otp =
      clean(
        req.body?.otp
      );

    if (
      !name ||
      !email ||
      !password ||
      !phone ||
      !otp
    ) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Please fill all required fields."
        });
    }

    if (
      password.length < 8
    ) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Password must be at least 8 characters."
        });
    }

    const savedOtp =
      otpStore.get(
        `register:${phone}`
      );

    if (
      !savedOtp ||
      savedOtp.expires <
        Date.now() ||
      savedOtp.otp !== otp
    ) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Invalid or expired OTP. Use 123456 in this development version."
        });
    }

    const users =
      await readUsers();

    if (
      users.some(
        user =>
          user.email ===
          email
      )
    ) {
      return res
        .status(409)
        .json({
          success: false,
          error:
            "An account with this email already exists."
        });
    }

    const user = {
      id:
        crypto.randomUUID(),

      name,

      email,

      phone,

      passwordHash:
        hashPassword(
          password
        ),

      location:
        "",

      crop:
        "",

      soil:
        "",

      irrigation:
        "",

      weather:
        ""
    };

    users.push(user);

    await writeUsers(
      users
    );

    otpStore.delete(
      `register:${phone}`
    );

    /*
      Save newly registered farmer
      to Firestore.
    */

    try {
      await saveFarmerToFirestore(
        user,
        {
          createdAt:
            Timestamp.now()
        }
      );
    } catch (firebaseError) {
      console.error(
        "FIRESTORE REGISTER ERROR:",
        firebaseError.message
      );
    }

    const token =
      createToken(user);

    res.json({
      success: true,

      token,

      user:
        publicUser(user)
    });
  }
);

/* =========================================================
   EMAIL LOGIN
   ========================================================= */

app.post(
  "/api/auth/login/email",
  async (req, res) => {
    const email =
      normalizeEmail(
        req.body?.email
      );

    const password =
      clean(
        req.body?.password
      );

    const users =
      await readUsers();

    const user =
      users.find(
        item =>
          item.email ===
          email
      );

    if (
      !user ||
      !verifyPassword(
        password,
        user.passwordHash
      )
    ) {
      return res
        .status(401)
        .json({
          success: false,
          error:
            "Invalid email or password."
        });
    }

    /*
      If Firestore has the farmer profile,
      load it and synchronize the profile
      fields into the current user.
    */

    try {
      const firebaseUser =
        await getFarmerFromFirestore(
          user.id
        );

      if (
        firebaseUser
      ) {
        user.location =
          clean(
            firebaseUser.location
          );

        user.crop =
          clean(
            firebaseUser.mainCrop
          );

        user.soil =
          clean(
            firebaseUser.soilType
          );

        user.irrigation =
          clean(
            firebaseUser.irrigationMethod
          );

        user.weather =
          clean(
            firebaseUser.currentWeather
          );
      }
    } catch (firebaseError) {
      console.warn(
        "FIRESTORE LOGIN READ:",
        firebaseError.message
      );
    }

    res.json({
      success: true,

      token:
        createToken(user),

      user:
        publicUser(user)
    });
  }
);

/* =========================================================
   PHONE LOGIN OTP
   ========================================================= */

app.post(
  "/api/auth/login/request-otp",
  async (req, res) => {
    const phone =
      normalizePhone(
        req.body?.phone
      );

    const users =
      await readUsers();

    if (
      !users.some(
        user =>
          user.phone ===
          phone
      )
    ) {
      return res
        .status(404)
        .json({
          success: false,
          error:
            "No account found for this phone number."
        });
    }

    const otp =
      "123456";

    otpStore.set(
      `login:${phone}`,
      {
        otp,

        expires:
          Date.now() +
          5 * 60 * 1000
      }
    );

    res.json({
      success: true,

      message:
        "OTP generated.",

      developmentOtp:
        otp
    });
  }
);

/* =========================================================
   PHONE LOGIN VERIFY
   ========================================================= */

app.post(
  "/api/auth/login/verify-otp",
  async (req, res) => {
    const phone =
      normalizePhone(
        req.body?.phone
      );

    const otp =
      clean(
        req.body?.otp
      );

    const savedOtp =
      otpStore.get(
        `login:${phone}`
      );

    if (
      !savedOtp ||
      savedOtp.expires <
        Date.now() ||
      savedOtp.otp !== otp
    ) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Invalid or expired OTP. Use 123456 in this development version."
        });
    }

    const users =
      await readUsers();

    const user =
      users.find(
        item =>
          item.phone ===
          phone
      );

    if (!user) {
      return res
        .status(404)
        .json({
          success: false,
          error:
            "Account not found."
        });
    }

    otpStore.delete(
      `login:${phone}`
    );

    /*
      Synchronize Firestore profile
      when available.
    */

    try {
      const firebaseUser =
        await getFarmerFromFirestore(
          user.id
        );

      if (
        firebaseUser
      ) {
        user.location =
          clean(
            firebaseUser.location
          );

        user.crop =
          clean(
            firebaseUser.mainCrop
          );

        user.soil =
          clean(
            firebaseUser.soilType
          );

        user.irrigation =
          clean(
            firebaseUser.irrigationMethod
          );

        user.weather =
          clean(
            firebaseUser.currentWeather
          );
      }
    } catch (firebaseError) {
      console.warn(
        "FIRESTORE OTP LOGIN READ:",
        firebaseError.message
      );
    }

    res.json({
      success: true,

      token:
        createToken(user),

      user:
        publicUser(user)
    });
  }
);

/* =========================================================
   FARM PROFILE
   ========================================================= */

app.post(
  "/api/profile",
  async (req, res) => {
    const email =
      normalizeEmail(
        req.body?.email
      );

    if (!email) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Email is required."
        });
    }

    const users =
      await readUsers();

    const user =
      users.find(
        item =>
          item.email ===
          email
      );

    if (!user) {
      return res
        .status(404)
        .json({
          success: false,
          error:
            "Farmer account not found."
        });
    }

    /*
      Update local user profile.
    */

    user.location =
      clean(
        req.body?.location
      );

    user.crop =
      clean(
        req.body?.crop
      );

    user.soil =
      clean(
        req.body?.soil
      );

    user.irrigation =
      clean(
        req.body?.irrigation
      );

    user.weather =
      clean(
        req.body?.weather
      );

    await writeUsers(
      users
    );

    /*
      IMPORTANT:
      Save the same farmer profile
      to Firestore.
    */

    let firebaseSaved =
      false;

    try {
      firebaseSaved =
        await saveFarmerToFirestore(
          user
        );
    } catch (firebaseError) {
      console.error(
        "FIRESTORE PROFILE SAVE ERROR:",
        firebaseError
      );
    }

    res.json({
      success: true,

      firebaseSaved,

      user:
        publicUser(user)
    });
  }
);

/* =========================================================
   FARMING ADVICE
   ========================================================= */

app.post(
  "/api/farming-advice",
  async (req, res) => {
    if (
      !requireGemini(res)
    ) {
      return;
    }

    const body =
      req.body || {};

    const problem =
      clean(
        body.problem ||
          body.userText ||
          body.message
      );

    const imageDataUrl =
      clean(
        body.image ||
          body.imageData
      );

    if (
      !problem &&
      !imageDataUrl
    ) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Please describe your farming problem or upload a crop photo."
        });
    }

    try {
      const prompt =
        farmingPrompt(
          body,
          problem
        );

      const advice =
        await callGemini({
          prompt,

          imageDataUrl
        });

      res.json({
        success: true,

        advice,

        text:
          advice,

        language:
          languageName(
            body.languageCode
          )
      });

    } catch (error) {
      console.error(
        "FARMING ADVICE ERROR:",
        error
      );

      res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "Unable to generate farming advice."
        });
    }
  }
);

/* =========================================================
   TWO-WAY VOICE / TEXT
   ========================================================= */

app.post(
  "/api/voice-chat",
  async (req, res) => {
    if (
      !requireGemini(res)
    ) {
      return;
    }

    const body =
      req.body || {};

    const transcript =
      clean(
        body.userText ||
          body.transcript ||
          body.text ||
          body.message
      );

    if (!transcript) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "No voice message was received."
        });
    }

    try {
      const prompt =
        farmingPrompt(
          body,
          transcript,
          "chat"
        );

      const answer =
        await callGemini({
          prompt
        });

      res.json({
        success: true,

        answer,

        text:
          answer,

        reply:
          answer,

        language:
          languageName(
            body.languageCode
          )
      });

    } catch (error) {
      console.error(
        "VOICE CHAT ERROR:",
        error
      );

      res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "Voice conversation failed."
        });
    }
  }
);

/* =========================================================
   GEMINI TEXT TO SPEECH
   ========================================================= */

app.post(
  "/api/tts",
  async (req, res) => {
    if (
      !requireGemini(res)
    ) {
      return;
    }

    const text =
      clean(
        req.body?.text
      );

    const language =
      languageName(
        req.body?.languageCode
      );

    if (!text) {
      return res
        .status(400)
        .json({
          success: false,
          error:
            "Text is required for speech."
        });
    }

    try {
      const response =
        await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
            GEMINI_TTS_MODEL
          )}:generateContent`,
          {
            method:
              "POST",

            headers: {
              "Content-Type":
                "application/json",

              "x-goog-api-key":
                GEMINI_API_KEY
            },

            body:
              JSON.stringify({
                contents: [
                  {
                    role:
                      "user",

                    parts: [
                      {
                        text:
                          `Speak this farming advice naturally in ${language}. Do not translate it to another language. Text:\n${text}`
                      }
                    ]
                  }
                ],

                generationConfig: {
                  responseModalities:
                    ["AUDIO"],

                  speechConfig: {
                    voiceConfig: {
                      voice:
                        "Kore"
                    }
                  }
                }
              })
          }
        );

      const raw =
        await response.text();

      let data;

      try {
        data =
          JSON.parse(raw);
      } catch {
        data = {
          error: {
            message:
              raw
          }
        };
      }

      if (
        !response.ok
      ) {
        throw new Error(
          data?.error?.message ||
            `Gemini TTS failed (${response.status}).`
        );
      }

      const parts =
        data
          ?.candidates?.[0]
          ?.content?.parts ||
        [];

      const audioPart =
        parts.find(
          part =>
            part?.inlineData?.data ||
            part?.inline_data?.data
        );

      const audio =
        audioPart
          ?.inlineData
          ?.data ||
        audioPart
          ?.inline_data
          ?.data;

      if (!audio) {
        throw new Error(
          "Gemini TTS returned no audio."
        );
      }

      res.json({
        success: true,

        audio,

        mimeType:
          "audio/wav",

        language
      });

    } catch (error) {
      console.error(
        "TTS ERROR:",
        error
      );

      res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "Speech generation failed."
        });
    }
  }
);

/* =========================================================
   FARMING RESOURCES
   ========================================================= */

app.post(
  "/api/resources",
  async (req, res) => {
    const crop =
      clean(
        req.body?.crop,
        "crop"
      );

    const problem =
      clean(
        req.body?.problem,
        "farming problem"
      );

    const videos =
      buildYouTubeLinks(
        crop,
        problem
      );

    const photos =
      await getWikimediaPhotos(
        crop,
        problem
      );

    res.json({
      success: true,

      videos,

      photos,

      youtubeAPI:
        "NOT USED"
    });
  }
);

/* =========================================================
   HOME
   ========================================================= */

app.get(
  "/",
  (_req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );
  }
);

/* =========================================================
   API 404
   ========================================================= */

app.use(
  "/api",
  (req, res) => {
    res
      .status(404)
      .json({
        success: false,

        error:
          `API route not found: ${req.method} ${req.path}`
      });
  }
);

/* =========================================================
   PAGE FALLBACK
   ========================================================= */

app.use(
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

app.listen(
  PORT,
  () => {
    console.log("");

    console.log(
      "🌱 Smart Farming Gemini server"
    );

    console.log(
      `Server: http://localhost:${PORT}`
    );

    console.log(
      `Health: http://localhost:${PORT}/api/health`
    );

    console.log(
      `Gemini: ${
        GEMINI_API_KEY
          ? "configured"
          : "MISSING GEMINI_API_KEY"
      }`
    );

    console.log(
      `Firebase: ${
        firebaseConfigured
          ? "configured"
          : "NOT CONFIGURED"
      }`
    );

    console.log(
      `Firebase project: ${FIREBASE_PROJECT_ID}`
    );

    console.log(
      `Firestore collection: farmers`
    );

    console.log(
      `Text/Image model: ${GEMINI_MODEL}`
    );

    console.log(
      `TTS model: ${GEMINI_TTS_MODEL}`
    );

    console.log(
      "YouTube API: NOT USED"
    );

    console.log("");
  }
);