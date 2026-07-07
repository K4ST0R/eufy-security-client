/*
 * archiveKeyDeriv.ts — Dérivation de la clé de déchiffrement des clips d'ARCHIVE
 * (history download) des stations eufy "mega" (PPCS_ENC_EEC), reversé de
 * libmega_media_sdk.so (gen_pic_code_v1 + helpers) et VALIDÉ bit-à-bit contre le device.
 *
 * key_data = genPicCodeV1(SN, DID, gTS)[0:16]  — que des valeurs PUBLIQUES, aucun secret :
 *   · SN  = numéro de série station          (ex "T8020P10220206E3")
 *   · DID = DID P2P "PREFIX-MIDDLE-SUFFIX"    (ex "EUPRAMA-047546-BZMDP")
 *   · gTS = timestamp interne 10 chiffres, fourni par la station dans le message
 *           CMD_DOWNLOAD_VIDEO du download exchange (à extraire à la réception)
 *   · ppcsSuffix = constante par device (dérivée du DID) — auto-calibrée via SPS H.264
 *
 * Frames : SEULES LES KEYFRAMES sont chiffrées (AES-128-ECB sur les 128 premiers o
 * du payload) ; les P-frames sont en clair.
 */
import { createHash, createDecipheriv } from "crypto";

function calPpcsIdSuffix(did: string, ppcsSuffixOverride?: number | null): number {
  if (ppcsSuffixOverride !== undefined && ppcsSuffixOverride !== null) return ppcsSuffixOverride | 0;
  const middle = String(did).split("-")[1] || "";
  // ppcs_hw_id (middle=6) / webrtc_hw_id (middle=9) non reversés -> override requis (auto-calibré).
  if (middle.length === 6 || middle.length === 9) {
    throw new Error("cal_ppcs_id_suffix: ppcsSuffix requis (hw_id non reversé) — auto-calibration");
  }
  return 100; // défaut confirmé dans l'asm
}

function genPicBaseCode(snid: string, did: string, ppcsSuffix?: number | null): string {
  const n = parseInt(snid[snid.length - 1], 16);
  const offset = (((Number.isNaN(n) ? 0 : n) % 10) + 10) % 10;
  return snid.slice(offset) + String(calPpcsIdSuffix(did, ppcsSuffix));
}

function genRandSeed(did: string, ts: string, ppcsSuffix?: number | null): string {
  const tsInt = parseInt(ts.slice(2), 10);
  const s = String(1000 - calPpcsIdSuffix(did, ppcsSuffix)) + String(tsInt);
  return createHash("md5").update(Buffer.from(s, "ascii")).digest("hex").toUpperCase();
}

function scrambleDigest(d: Buffer): Buffer {
  const out = Buffer.from(d);
  for (let i = 0; i < 32; i++) {
    const c = out[i];
    const nx = i === 31 ? out[10] : out[i + 1];
    if ((i & 1) === 0) {
      if (c < 0x7d || nx <= 0x7c) out[i] = (c + nx) & 0xff;
    } else {
      if (c > 0x7e || nx >= 0x7f) out[i] = (c > nx ? c - nx : nx - c) & 0xff;
    }
  }
  return out;
}

function genCheckCodeV1(baseCode: string, randSeed: string): string {
  const d = createHash("sha256").update(Buffer.from("01" + baseCode + randSeed, "ascii")).digest();
  return scrambleDigest(d).slice(16, 32).toString("hex").toUpperCase();
}

/** check_code complet (32 hex). key_data = check_code[0:16]. */
export function genPicCodeV1(snid: string, did: string, ts: string, ppcsSuffix?: number | null): string {
  if (!snid || !did || !ts) throw new Error("archive key: argument manquant");
  if (did.length < 10) throw new Error("archive key: DID trop court");
  if (ts.length !== 10) throw new Error("archive key: gTS attendu = 10 chiffres");
  return genCheckCodeV1(genPicBaseCode(snid, did, ppcsSuffix), genRandSeed(did, ts, ppcsSuffix));
}

/** key_data (16 chars ASCII) pour un clip. */
export function deriveArchiveKeyData(sn: string, did: string, gts: string, ppcsSuffix?: number | null): string {
  return genPicCodeV1(sn, did, String(gts).padStart(10, "0"), ppcsSuffix).slice(0, 16);
}

/** Extrait le gTS (1ère string de 10 chiffres) d'un message P2P CMD_DOWNLOAD_VIDEO. */
export function extractArchiveGTS(msgData: Buffer): string | null {
  const m = msgData.toString("latin1").match(/(?<!\d)\d{10}(?!\d)/);
  return m ? m[0] : null;
}

const NAL_START = Buffer.from([0x00, 0x00, 0x00, 0x01]);
/**
 * Une keyframe déchiffrée commence par un start code + un NAL de début de keyframe :
 *  - SPS (type 7) : la 1re keyframe du flux (SPS+PPS+IDR) -> 0x27/0x67/...
 *  - IDR slice (type 5) : les keyframes SUIVANTES commencent souvent direct par l'IDR -> 0x25/0x65/...
 * Ne valider que le SPS (ancien code) laissait les IDR chiffrées -> demi-image sur le reste du clip.
 * On teste le type NAL (5 bits de poids faible), indépendamment du nal_ref_idc.
 */
function isKeyframeStart(out: Buffer): boolean {
  if (!out.subarray(0, 4).equals(NAL_START)) return false;
  const nalType = out[4] & 0x1f;
  return nalType === 7 || nalType === 5;
}

/**
 * Dérive key_data pour une keyframe, en auto-calibrant ppcsSuffix (constante/device) :
 * cherche le suffixe dont le déchiffrement des 128 premiers o donne un SPS H.264.
 * Retourne { keyData, ppcsSuffix } ou null. Une fois trouvé, réutiliser le suffixe (cache appelant).
 */
export function deriveArchiveKeyCalibrated(
  sn: string,
  did: string,
  gts: string,
  keyframeEnc128: Buffer,
  knownSuffix?: number | null,
  maxSuffix = 8192
): { keyData: string; ppcsSuffix: number } | null {
  const gts10 = String(gts).padStart(10, "0");
  const test = (suffix: number): string | null => {
    let kd: string;
    try {
      kd = genPicCodeV1(sn, did, gts10, suffix).slice(0, 16);
    } catch {
      return null;
    }
    const dec = createDecipheriv("aes-128-ecb", Buffer.from(kd, "ascii"), null);
    dec.setAutoPadding(false);
    let out: Buffer;
    try {
      out = Buffer.concat([dec.update(keyframeEnc128.subarray(0, 128)), dec.final()]);
    } catch {
      return null;
    }
    return isKeyframeStart(out) ? kd : null;
  };
  if (knownSuffix !== undefined && knownSuffix !== null) {
    const kd = test(knownSuffix);
    if (kd) return { keyData: kd, ppcsSuffix: knownSuffix };
  }
  for (let s = 0; s <= maxSuffix; s++) {
    const kd = test(s);
    if (kd) return { keyData: kd, ppcsSuffix: s };
  }
  return null;
}
