declare module "ogg-opus-decoder" {
  export type SpeechQualityEnhancement = "none" | "lace" | "nolace";

  export interface OggOpusDecodeOptions {
    forceStereo?: boolean;
    speechQualityEnhancement?: SpeechQualityEnhancement;
    sampleRate?: 8000 | 12000 | 16000 | 24000 | 48000;
  }

  export interface OggOpusDecodeResult {
    channelData: Float32Array[];
    samplesDecoded: number;
    sampleRate: number;
    errors?: Array<{
      message: string;
      frameLength: number;
      frameNumber: number;
      inputBytes: number;
      outputSamples: number;
    }>;
  }

  export class OggOpusDecoder {
    constructor(options?: OggOpusDecodeOptions);
    readonly ready: Promise<void>;
    decode(data: Uint8Array): Promise<OggOpusDecodeResult>;
    decodeFile(data: Uint8Array): Promise<OggOpusDecodeResult>;
    flush(): Promise<OggOpusDecodeResult>;
    reset(): Promise<void>;
    free(): void;
  }

  export class OggOpusDecoderWebWorker {
    constructor(options?: OggOpusDecodeOptions);
    readonly ready: Promise<void>;
    decode(data: Uint8Array): Promise<OggOpusDecodeResult>;
    decodeFile(data: Uint8Array): Promise<OggOpusDecodeResult>;
    flush(): Promise<OggOpusDecodeResult>;
    reset(): Promise<void>;
    free(): Promise<void>;
  }
}
