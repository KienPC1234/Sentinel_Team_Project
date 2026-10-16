'use client';
/* Port từ PKV/templates/Scan/scan_audio.html — Quét Âm Thanh.
 * API: POST /api/v1/scan/audio/ (FormData: audio, cf-turnstile-response)
 *      → {scan_id} rồi WS /ws/scan/<id>/ + poll GET /scan/status/<id>/.
 */
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select';
import {
  ScanGuide,
  TurnstileWidget,
  getTsToken,
  resetTurnstile,
  showToast,
  useScanTracker,
} from '../../components/ScanWidgets';
import type { ScanResult, TrackerDone } from '../../components/ScanWidgets';
import { asStr, asNum, asArr, guardrailTone, guardrailLabel, TrustGuardrailPanel } from '../../components/ScanWidgets';

interface AudioSegment {
  start?: number;
  text?: string;
}

interface AudioDevice {
  deviceId: string;
  label: string;
}

function formatBytes(bytes: number, decimals = 2): string {
  if (!bytes) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60).toString().padStart(2, '0');
  const s = (seconds % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

function formatTimestamp(seconds: unknown): string {
  if (typeof seconds !== 'number') return '00:00';
  const m = Math.floor(seconds / 60).toString().padStart(2, '0');
  const s =  Math.floor(seconds % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

export default function Audio() {
  const [mode, setMode] = useState<'upload' | 'record'>('upload');
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [trackOn, setTrackOn] = useState(false);
  const [liveTranscript, setLiveTranscript] = useState('');

  const [isRecording, setIsRecording] = useState(false);
  const [processingRecording, setProcessingRecording] = useState(false);
  const [recordedBlob, setRecordedBlob] = useState<Blob | null>(null);
  const [recordingDuration, setRecordingDuration] = useState(0);
  const [audioDevices, setAudioDevices] = useState<AudioDevice[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState('');
  const [micTesting, setMicTesting] = useState(false);
  const [micLevel, setMicLevel] = useState(0);

  const audioInputRef = useRef<HTMLInputElement>(null);
  const audioPreviewRef = useRef<HTMLAudioElement>(null);
  const recordedPreviewRef = useRef<HTMLAudioElement>(null);
  const waveCanvasRef = useRef<HTMLCanvasElement>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const streamRef = useRef<MediaStream | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const animRef = useRef<number>(0);
  const timerRef = useRef<number | null>(null);
  const micTestRef = useRef<{ stream: MediaStream | null; frame: number }>({ stream: null, frame: 0 });

  const MAX_RECORD = 1800;
  const MIN_RECORD = 2;

  const tracker = useScanTracker(scanId, {
    enabled: trackOn && scanId != null,
    onDone: (d: TrackerDone) => {
      const merged = { ...d.result, risk_score: d.risk_score, risk_level: d.risk_level };
      setResult(merged);
      setLoading(false);
      setScanning(false);
      setTrackOn(false);
    },
    onError: (msg: string) => {
      showToast(msg, 'error');
      setLoading(false);
      setScanning(false);
      setTrackOn(false);
    },
    onTranscript: (t: string) => setLiveTranscript(t),
  });

  const hasAudio = (mode === 'upload' && audioFile) || (mode === 'record' && recordedBlob);

  const refreshDevices = async (): Promise<void> => {
    try {
      const temp = await navigator.mediaDevices.getUserMedia({ audio: true });
      temp.getTracks().forEach((t) => t.stop());
      const devices = await navigator.mediaDevices.enumerateDevices();
      setAudioDevices(
        devices.filter((d) => d.kind === 'audioinput').map((d, i) => ({ deviceId: d.deviceId, label: d.label || `Microphone ${i + 1}` })),
      );
    } catch {
      setAudioDevices([]);
    }
  };

  useEffect(() => {
    void refreshDevices();
    return () => {
      if (timerRef.current != null) window.clearInterval(timerRef.current);
      cancelAnimationFrame(animRef.current);
      streamRef.current?.getTracks().forEach((t) => t.stop());
      if (micTestRef.current.stream) micTestRef.current.stream.getTracks().forEach((t) => t.stop());
      cancelAnimationFrame(micTestRef.current.frame);
    };
  }, []);

  const stopMicTest = (): void => {
    setMicTesting(false);
    setMicLevel(0);
    cancelAnimationFrame(micTestRef.current.frame);
    micTestRef.current.stream?.getTracks().forEach((t) => t.stop());
    micTestRef.current.stream = null;
  };

  const testSelectedMic = async (): Promise<void> => {
    stopMicTest();
    try {
      const constraints: MediaStreamConstraints = {
        audio: selectedDeviceId ? { deviceId: { exact: selectedDeviceId } } : true,
      };
      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      micTestRef.current.stream = stream;
      setMicTesting(true);
      const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      const ctx = new Ctx();
      if (ctx.state === 'suspended') await ctx.resume();
      const source = ctx.createMediaStreamSource(stream);
      const analyser = ctx.createAnalyser();
      analyser.fftSize = 256;
      source.connect(analyser);
      const dataArray = new Uint8Array(analyser.frequencyBinCount);
      const update = (): void => {
        analyser.getByteFrequencyData(dataArray);
        let sum = 0;
        for (let i = 0; i < dataArray.length; i++) sum += dataArray[i];
        setMicLevel(Math.min(100, (sum / dataArray.length) * 1.5));
        micTestRef.current.frame = requestAnimationFrame(update);
      };
      update();
      window.setTimeout(() => stopMicTest(), 5000);
    } catch (err) {
      showToast('Không thể truy cập micro đã chọn: ' + (err instanceof Error ? err.message : ''), 'error');
      setMicTesting(false);
    }
  };

  const setFile = (f: File): void => {
    setAudioFile(f);
    setResult(null);
    window.setTimeout(() => {
      if (audioPreviewRef.current) audioPreviewRef.current.src = URL.createObjectURL(f);
    }, 0);
  };

  const drawWaveform = (): void => {
    const canvas = waveCanvasRef.current;
    const analyser = analyserRef.current;
    if (!canvas || !analyser) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const bufferLength = analyser.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);
    const draw = (): void => {
      animRef.current = requestAnimationFrame(draw);
      analyser.getByteFrequencyData(dataArray);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const barCount = 64;
      const barWidth = canvas.width / barCount - 1;
      const step = Math.floor(bufferLength / barCount);
      for (let i = 0; i < barCount; i++) {
        const val = dataArray[i * step] / 255;
        const barHeight = Math.max(2, val * canvas.height * 0.9);
        const x = i * (barWidth + 1);
        const y = (canvas.height - barHeight) / 2;
        const gradient = ctx.createLinearGradient(0, y, 0, y + barHeight);
        gradient.addColorStop(0, `rgba(139, 92, 246, ${0.3 + val * 0.7})`);
        gradient.addColorStop(1, `rgba(217, 70, 239, ${0.2 + val * 0.6})`);
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.roundRect(x, y, barWidth, barHeight, 2);
        ctx.fill();
      }
    };
    draw();
  };

  const stopWaveform = (): void => {
    cancelAnimationFrame(animRef.current);
    if (audioCtxRef.current) {
      audioCtxRef.current.close().catch(() => undefined);
      audioCtxRef.current = null;
    }
  };

  const startRecording = async (): Promise<void> => {
    stopMicTest();
    try {
      const audioConstraints: MediaTrackConstraints = {
        echoCancellation: true,
        noiseSuppression: false,
        autoGainControl: true,
        sampleRate: 44100,
        channelCount: 1,
      };
      if (selectedDeviceId) audioConstraints.deviceId = { exact: selectedDeviceId };
      const stream = await navigator.mediaDevices.getUserMedia({ audio: audioConstraints });
      const track = stream.getAudioTracks()[0];
      if (!track || track.readyState !== 'live') {
        showToast('Microphone không hoạt động. Vui lòng kiểm tra thiết bị.', 'error');
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      chunksRef.current = [];
      setRecordingDuration(0);
      setRecordedBlob(null);
      streamRef.current = stream;

      const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      const audioCtx = new Ctx({ sampleRate: 44100 });
      if (audioCtx.state === 'suspended') await audioCtx.resume();
      audioCtxRef.current = audioCtx;
      const source = audioCtx.createMediaStreamSource(stream);
      const gainNode = audioCtx.createGain();
      gainNode.gain.value = 2.5;
      const analyser = audioCtx.createAnalyser();
      analyser.fftSize = 256;
      analyserRef.current = analyser;
      const destination = audioCtx.createMediaStreamDestination();
      source.connect(gainNode);
      gainNode.connect(analyser);
      gainNode.connect(destination);

      const candidates = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/webm', 'audio/mp4', ''];
      let mimeType = '';
      for (const mt of candidates) {
        if (!mt || MediaRecorder.isTypeSupported(mt)) {
          mimeType = mt;
          break;
        }
      }
      const recOpts: MediaRecorderOptions = { audioBitsPerSecond: 128000 };
      if (mimeType) recOpts.mimeType = mimeType;
      const recorder = new MediaRecorder(destination.stream, recOpts);
      recorderRef.current = recorder;
      recorder.ondataavailable = (e: BlobEvent) => {
        if (e.data && e.data.size > 0) chunksRef.current.push(e.data);
      };
      recorder.onstop = () => {
        const blob = new Blob(chunksRef.current, { type: mimeType || 'audio/webm' });
        setRecordedBlob(blob);
        setProcessingRecording(false);
        streamRef.current?.getTracks().forEach((t) => t.stop());
        destination.stream.getTracks().forEach((t) => t.stop());
        stopWaveform();
        if (recordingDuration < MIN_RECORD) {
          showToast('Ghi âm quá ngắn (tối thiểu 2 giây). Vui lòng thử lại.', 'warning');
          setRecordedBlob(null);
          return;
        }
        if (blob.size < 100) {
          showToast('Ghi âm rỗng. Microphone có thể không hoạt động đúng.', 'error');
          setRecordedBlob(null);
          return;
        }
        window.setTimeout(() => {
          if (recordedPreviewRef.current) recordedPreviewRef.current.src = URL.createObjectURL(blob);
        }, 0);
      };
      recorder.onerror = () => {
        showToast('Lỗi ghi âm không xác định', 'error');
        stopRecording();
      };
      recorder.start(100);
      setIsRecording(true);
      timerRef.current = window.setInterval(() => {
        setRecordingDuration((d) => {
          if (d + 1 >= MAX_RECORD) {
            showToast('Đã đạt thời gian tối đa (30 phút). Tự động dừng.', 'info');
            stopRecording();
          }
          return d + 1;
        });
      }, 1000);
      drawWaveform();
    } catch (err) {
      const name = err instanceof Error ? err.name : '';
      if (name === 'NotAllowedError') {
        showToast('Bạn đã từ chối quyền truy cập microphone. Vui lòng cấp quyền trong cài đặt trình duyệt.', 'error');
      } else if (name === 'NotFoundError') {
        showToast('Không tìm thấy microphone. Vui lòng kiểm tra thiết bị.', 'error');
      } else if (name === 'NotReadableError' || name === 'AbortError') {
        showToast('Microphone đang bận hoặc không thể đọc. Thử chọn thiết bị khác.', 'error');
      } else if (name === 'OverconstrainedError') {
        showToast('Micro đã chọn không khả dụng. Đang thử micro mặc định...', 'warning');
        setSelectedDeviceId('');
      } else {
        showToast('Không thể truy cập microphone: ' + (err instanceof Error ? err.message : ''), 'error');
      }
    }
  };

  const stopRecording = (): void => {
    setIsRecording(false);
    setProcessingRecording(true);
    if (timerRef.current != null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    stopWaveform();
    const rec = recorderRef.current;
    if (rec) {
      try {
        if (rec.state === 'recording' || rec.state === 'paused') {
          rec.stop();
        } else if (chunksRef.current.length > 0) {
          setRecordedBlob(new Blob(chunksRef.current, { type: rec.mimeType || 'audio/webm' }));
          setProcessingRecording(false);
          streamRef.current?.getTracks().forEach((t) => t.stop());
        } else {
          setProcessingRecording(false);
        }
      } catch {
        setProcessingRecording(false);
        streamRef.current?.getTracks().forEach((t) => t.stop());
      }
    }
  };

  const discardRecording = (): void => {
    setRecordedBlob(null);
    chunksRef.current = [];
    setRecordingDuration(0);
    setProcessingRecording(false);
  };

  const resetAll = (): void => {
    setAudioFile(null);
    setRecordedBlob(null);
    chunksRef.current = [];
    setRecordingDuration(0);
    setResult(null);
    setLoading(false);
    setScanning(false);
    setLiveTranscript('');
    setScanId(null);
    setTrackOn(false);
    tracker.clear();
    stopMicTest();
    if (audioInputRef.current) audioInputRef.current.value = '';
  };

  const startScan = (): void => {
    if (!hasAudio) return;
    if (mode === 'record' && recordedBlob && recordingDuration < MIN_RECORD) {
      showToast('Ghi âm quá ngắn. Vui lòng ghi âm ít nhất 2 giây.', 'warning');
      return;
    }
    const tsToken = getTsToken();
    if (!tsToken) {
      showToast('Vui lòng hoàn thành xác minh anti-spam.', 'warning');
      return;
    }
    try {
      resetTurnstile();
    } catch {
      /* bỏ qua */
    }
    setLoading(true);
    setScanning(false);
    setLiveTranscript('');
    setResult(null);
    setScanId(null);
    setTrackOn(false);
    tracker.clear();
    tracker.push('Đang tải âm thanh lên hệ thống...', 'uploading');

    const formData = new FormData();
    if (mode === 'upload' && audioFile) {
      formData.append('audio', audioFile);
    } else if (mode === 'record' && recordedBlob) {
      const ext = recordedBlob.type.includes('ogg') ? 'ogg' : 'webm';
      formData.append('audio', recordedBlob, `recording.${ext}`);
    }
    formData.append('cf-turnstile-response', tsToken);

    api
      .upload<{ scan_id?: number; error?: string }>('/scan/audio/', formData)
      .then((data) => {
        if (typeof data.scan_id === 'number') {
          setScanId(data.scan_id);
          setScanning(true);
          setTrackOn(true);
        } else {
          showToast(data.error || 'Không thể xử lý tệp âm thanh.', 'error');
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        showToast(e instanceof Error ? e.message : 'Lỗi kết nối máy chủ hoặc gián đoạn đường truyền tải file.', 'error');
        setLoading(false);
      });
  };

  const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);
  const segments = asArr<AudioSegment>(result?.['segments']);
  const webSources = asArr<string>(result?.['web_sources']);
  const duration = result?.['duration'];

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="space-y-10">
        <div className="text-center space-y-5">
          <div className="relative inline-block">
            <div className="absolute inset-0 bg-brand2-500 blur-3xl opacity-20 rounded-full scale-150"></div>
            <div className="relative inline-flex items-center justify-center w-20 h-20 rounded-[2rem] bg-brand2-500/10 text-brand2-400 border border-brand2-500/20 shadow-lg shadow-brand2-500/10">
              <i className="bi bi-soundwave text-4xl"></i>
            </div>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight leading-none">
            Quét <span className="glow-text text-brand2-400">Âm Thanh</span>
          </h1>
          <p className="text-white/55 max-w-lg mx-auto text-sm leading-relaxed">
            Tải lên cuộc gọi ghi âm hoặc ghi âm trực tiếp: AI sẽ chuyển đổi giọng nói thành văn bản và phân tích dấu hiệu lừa đảo trong hội thoại.
          </p>
        </div>

        {!result && (
          <div className="liquid-card p-0 relative group overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-brand2-500/5 to-brand-500/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>

            <div className="relative z-10 flex border-b border-white/5">
              <button
                type="button"
                onClick={() => setMode('upload')}
                className={`flex-1 py-5 text-center text-[11px] font-black uppercase tracking-[0.2em] transition-all border-b-2 relative ${
                  mode === 'upload' ? 'text-brand2-400 border-brand2-500 bg-brand2-500/5' : 'text-white/45 border-transparent hover:text-white/60'
                }`}
              >
                <i className="bi bi-cloud-arrow-up-fill mr-2 text-lg align-middle"></i>Tải File
              </button>
              <button
                type="button"
                onClick={() => setMode('record')}
                className={`flex-1 py-5 text-center text-[11px] font-black uppercase tracking-[0.2em] transition-all border-b-2 relative ${
                  mode === 'record' ? 'text-brand2-400 border-brand2-500 bg-brand2-500/5' : 'text-white/45 border-transparent hover:text-white/60'
                }`}
              >
                <i className="bi bi-mic-fill mr-2 text-lg align-middle"></i>Ghi Âm
              </button>
            </div>

            <div className="relative z-10 p-6 sm:p-10">
              {mode === 'upload' && (
                <div>
                  {!audioFile && (
                    <div
                      className={`flex flex-col items-center justify-center py-16 border-2 border-dashed border-white/10 rounded-3xl hover:border-brand2-500/30 transition-all cursor-pointer group/drop ${dragging ? 'bg-brand2-500/10 border-brand2-500/50 scale-[0.99]' : ''}`}
                      onClick={() => audioInputRef.current?.click()}
                      onDragOver={(e) => {
                        e.preventDefault();
                        setDragging(true);
                      }}
                      onDragLeave={(e) => {
                        e.preventDefault();
                        setDragging(false);
                      }}
                      onDrop={(e) => {
                        e.preventDefault();
                        setDragging(false);
                        const f = e.dataTransfer.files[0];
                        if (f) setFile(f);
                      }}
                    >
                      <input
                        type="file"
                        ref={audioInputRef}
                        accept=".mp3,.m4a,.wav,.ogg,.webm,.flac,.aac,audio/*"
                        className="hidden"
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) setFile(f);
                        }}
                      />
                      <div className="relative mb-6">
                        <div className="absolute inset-0 bg-brand2-500/20 blur-2xl rounded-full scale-150 opacity-0 group-hover/drop:opacity-100 transition-opacity"></div>
                        <div className="relative w-20 h-20 rounded-[1.5rem] bg-white/[0.03] border border-white/10 flex items-center justify-center group-hover/drop:border-brand2-500/30 group-hover/drop:scale-110 transition-all duration-300">
                          <i className="bi bi-file-earmark-music text-4xl text-white/15 group-hover/drop:text-brand2-400/60 transition-colors"></i>
                        </div>
                      </div>
                      <p className="text-white font-black text-lg mb-2">Click hoặc kéo thả file âm thanh</p>
                      <p className="text-white/45 text-xs font-bold">MP3 · WAV · M4A · OGG · WebM · FLAC · AAC <span className="text-white/15 ml-1">Tối đa 50MB</span></p>
                    </div>
                  )}

                  {audioFile && (
                    <div className="space-y-5">
                      <div className="bg-white/[0.02] rounded-2xl p-5 border border-white/10 flex items-center gap-5">
                        <div className="relative">
                          <div className="absolute inset-0 bg-brand2-500 blur-xl opacity-20"></div>
                          <div className="relative w-14 h-14 rounded-2xl bg-brand2-500/10 flex items-center justify-center text-brand2-400 text-2xl border border-brand2-500/20">
                            <i className="bi bi-file-earmark-music-fill"></i>
                          </div>
                        </div>
                        <div className="flex-1 min-w-0">
                          <h4 className="text-white font-black truncate text-sm">{audioFile.name}</h4>
                          <p className="text-white/45 text-[11px] font-bold mt-0.5">{formatBytes(audioFile.size)}</p>
                        </div>
                        {!loading && (
                          <button
                            type="button"
                            onClick={() => {
                              setAudioFile(null);
                              setResult(null);
                              if (audioInputRef.current) audioInputRef.current.value = '';
                            }}
                            className="w-10 h-10 rounded-xl bg-white/5 hover:bg-danger-500/10 text-white/35 hover:text-danger-400 flex items-center justify-center transition-all"
                          >
                            <i className="bi bi-trash3 text-sm"></i>
                          </button>
                        )}
                      </div>
                      <audio ref={audioPreviewRef} controls className="w-full rounded-xl"></audio>
                    </div>
                  )}
                </div>
              )}

              {mode === 'record' && (
                <div className="space-y-6">
                  {!isRecording && (
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                      <div className="flex-1 relative">
                        <div className="absolute left-4 top-1/2 -translate-y-1/2 text-white/55 pointer-events-none z-10">
                          <i className="bi bi-mic"></i>
                        </div>
                        <Select
                          value={selectedDeviceId || 'default'}
                          onValueChange={(v) => {
                            setSelectedDeviceId(v === 'default' ? '' : v);
                            void testSelectedMic();
                          }}
                        >
                          <SelectTrigger
                            className="w-full bg-white/[0.03] border border-white/10 text-white/80 text-sm font-bold rounded-xl pl-11 pr-10 py-3 h-auto focus:border-brand2-500/50 cursor-pointer"
                            aria-label="Chọn micro"
                          >
                            <SelectValue placeholder="Micro mặc định" />
                          </SelectTrigger>
                          <SelectContent className="max-h-72">
                            <SelectItem value="default">Micro mặc định</SelectItem>
                            {audioDevices.map((d) => (
                              <SelectItem key={d.deviceId} value={d.deviceId}>{d.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <button
                        type="button"
                        onClick={() => void refreshDevices()}
                        className="px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white/55 hover:text-brand2-400 hover:border-brand2-500/30 transition-all text-xs font-black uppercase tracking-widest"
                        title="Làm mới danh sách micro"
                      >
                        <i className="bi bi-arrow-clockwise"></i>
                      </button>
                    </div>
                  )}

                  {micTesting && !isRecording && (
                    <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] font-black text-white/45 uppercase tracking-widest shrink-0">Mức thu</span>
                      <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-100 ${micLevel > 60 ? 'bg-safe-500' : micLevel > 20 ? 'bg-warn-400' : 'bg-white/20'}`}
                          style={{ width: `${micLevel}%` }}
                        ></div>
                      </div>
                      <span className="text-[10px] font-mono text-white/35">{Math.round(micLevel)}%</span>
                    </div>
                  )}

                  <div className="flex flex-col items-center py-8">
                    <div className="relative mb-6">
                      {isRecording && (
                        <div className="absolute -inset-4">
                          <svg className="w-full h-full animate-spin-slow" viewBox="0 0 160 160">
                            <circle cx="80" cy="80" r="76" fill="none" stroke="rgba(239,68,68,0.15)" strokeWidth="2" strokeDasharray="8 12" />
                          </svg>
                        </div>
                      )}
                      {isRecording && <div className="absolute -inset-6 rounded-full bg-danger-500/10 animate-ping"></div>}
                      {isRecording && <div className="absolute -inset-3 rounded-full bg-danger-500/5 animate-pulse"></div>}

                      <button
                        type="button"
                        onClick={() => {
                          if (isRecording) stopRecording();
                          else void startRecording();
                        }}
                        disabled={processingRecording}
                        className={`relative w-28 h-28 rounded-full flex items-center justify-center text-4xl transition-all duration-500 z-10 shadow-2xl ${
                          isRecording
                            ? 'bg-gradient-to-br from-danger-500 to-danger-600 text-white shadow-danger-500/40 scale-110 hover:from-danger-400 hover:to-danger-500'
                            : processingRecording
                              ? 'bg-white/[0.03] text-white/15 border-2 border-white/5 cursor-not-allowed'
                              : 'bg-white/[0.03] text-white/45 border-2 border-white/10 hover:border-brand2-500/50 hover:text-brand2-400 hover:shadow-brand2-500/20 hover:scale-105'
                        }`}
                      >
                        <i className={isRecording ? 'bi bi-stop-fill' : processingRecording ? 'bi bi-hourglass-split animate-pulse' : 'bi bi-mic-fill'}></i>
                      </button>
                    </div>

                    <div className="text-center space-y-2">
                      {!isRecording && !recordedBlob && !processingRecording && (
                        <p className="text-white/55 text-sm font-bold">Nhấn để bắt đầu ghi âm</p>
                      )}
                      {processingRecording && !recordedBlob && (
                        <div className="flex items-center justify-center gap-2">
                          <svg className="animate-spin w-4 h-4 text-brand2-400" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                          </svg>
                          <span className="text-brand2-400 text-sm font-bold">Đang xử lý bản ghi...</span>
                        </div>
                      )}
                      {isRecording && (
                        <div className="space-y-3">
                          <p className="text-danger-400 text-sm font-black animate-pulse flex items-center justify-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-danger-500 shadow-lg shadow-danger-500/50"></span>
                            Đang ghi âm: <span>{formatTime(recordingDuration)}</span>
                            <span className="text-white/15 text-xs">/ {formatTime(MAX_RECORD)}</span>
                          </p>
                          <canvas ref={waveCanvasRef} width={320} height={64} className="rounded-2xl mx-auto bg-white/[0.03] border border-white/5"></canvas>
                        </div>
                      )}
                    </div>
                  </div>

                  {recordedBlob && !isRecording && (
                    <div className="space-y-4 animate-fadein">
                      <div className="bg-white/[0.02] rounded-2xl p-5 border border-safe-500/10 flex items-center gap-5">
                        <div className="relative">
                          <div className="absolute inset-0 bg-safe-500 blur-xl opacity-20"></div>
                          <div className="relative w-14 h-14 rounded-2xl bg-safe-500/10 flex items-center justify-center text-safe-400 text-2xl border border-safe-500/20">
                            <i className="bi bi-check-circle-fill"></i>
                          </div>
                        </div>
                        <div className="flex-1 min-w-0">
                          <h4 className="text-white font-black text-sm">Bản ghi âm hoàn tất</h4>
                          <p className="text-white/45 text-[11px] font-bold mt-0.5">{formatTime(recordingDuration)} • {formatBytes(recordedBlob.size)}</p>
                        </div>
                        {!loading && (
                          <button type="button" onClick={discardRecording} className="w-10 h-10 rounded-xl bg-white/5 hover:bg-danger-500/10 text-white/35 hover:text-danger-400 flex items-center justify-center transition-all">
                            <i className="bi bi-trash3 text-sm"></i>
                          </button>
                        )}
                      </div>
                      <audio ref={recordedPreviewRef} controls className="w-full rounded-xl"></audio>
                    </div>
                  )}
                </div>
              )}

              {hasAudio && !loading && !scanning && (
                <div className="mt-8 flex flex-col items-center gap-6">
                  <TurnstileWidget />
                  <button type="button" onClick={startScan} className="relative group/scan overflow-hidden rounded-2xl w-full sm:w-auto">
                    <div className="absolute inset-0 bg-gradient-to-r from-brand2-600 to-brand-600 opacity-0 group-hover/scan:opacity-100 transition-opacity"></div>
                    <div className="relative bg-brand2-500 hover:bg-brand2-400 text-white px-14 py-4 rounded-2xl font-black text-[11px] uppercase tracking-[0.3em] shadow-xl shadow-brand2-500/25 flex items-center justify-center gap-3 transition-all group-hover/scan:scale-[1.02]">
                      <i className="bi bi-shield-shaded text-lg"></i> Phân tích âm thanh
                    </div>
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {(loading || scanning) && tracker.progress.length > 0 && (
          <div className="liquid-card p-6 border-brand2-500/20 bg-brand2-500/[0.02] animate-fadein overflow-hidden">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h4 className="text-[10px] font-black text-brand2-400 uppercase tracking-[0.2em] flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-brand2-500 animate-pulse"></span>
                Nhật ký phân tích
              </h4>
              <div className="flex items-center gap-3">
                <span className="text-[10px] text-white/35 font-mono">{tracker.progress.length} bước</span>
                <div
                  className={`text-[10px] font-black uppercase tracking-wider px-2.5 py-1 rounded-lg border ${
                    tracker.wsState === 'connected'
                      ? 'text-safe-400 border-safe-500/20 bg-safe-500/5'
                      : tracker.wsState === 'reconnecting' || tracker.wsState === 'connecting'
                        ? 'text-warn-400 border-warn-500/20 bg-warn-500/5'
                        : 'text-danger-400 border-danger-500/20 bg-danger-500/5'
                  }`}
                >
                  {tracker.wsState === 'connected' ? 'LIVE' : tracker.wsState === 'reconnecting' ? 'RETRY' : tracker.wsState === 'connecting' ? '...' : 'OFFLINE'}
                </div>
              </div>
            </div>
            <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden mb-5">
              <div
                className="h-full bg-gradient-to-r from-brand2-500/50 to-brand-500/50 transition-all duration-700 rounded-full"
                style={{ width: `${Math.min(95, tracker.progress.length * 20)}%` }}
              ></div>
            </div>
            <div className="space-y-3 font-mono text-[11px] max-h-[300px] overflow-y-auto custom-scrollbar">
              {tracker.progress.map((item, index) => (
                <div key={index} className="flex items-start gap-3 animate-fadein">
                  <span
                    className={`flex-shrink-0 mt-0.5 ${
                      item.step === 'completed'
                        ? 'text-safe-500'
                        : item.step === 'error'
                          ? 'text-danger-500'
                          : item.step === 'transcribing'
                            ? 'text-brand-400'
                            : item.step === 'transcribed'
                              ? 'text-safe-400'
                              : item.step === 'analyzing' || item.step === 'analyzed'
                                ? 'text-warn-400'
                                : 'text-brand2-500/50'
                    }`}
                  >
                    <i
                      className={`bi ${
                        item.step === 'completed'
                          ? 'bi-check-circle-fill'
                          : item.step === 'error'
                            ? 'bi-x-circle-fill'
                            : item.step === 'transcribing'
                              ? 'bi-soundwave'
                              : item.step === 'transcribed'
                                ? 'bi-chat-left-text-fill'
                                : item.step === 'analyzing' || item.step === 'analyzed'
                                  ? 'bi-cpu-fill'
                                  : index === tracker.progress.length - 1
                                    ? 'bi-arrow-right'
                                    : 'bi-dot'
                      }`}
                    ></i>
                  </span>
                  <span className="text-white/80 flex-1">{item.message}</span>
                  {index === tracker.progress.length - 1 && item.step !== 'completed' && (
                    <i className="bi bi-three-dots animate-pulse text-brand2-400 flex-shrink-0"></i>
                  )}
                </div>
              ))}
            </div>

            {liveTranscript && (
              <div className="mt-5 p-4 rounded-2xl bg-white/[0.02] border border-white/5">
                <div className="text-[9px] font-black text-white/35 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                  <i className="bi bi-chat-left-text text-brand2-400/40"></i> Bản ghi nhận dạng
                </div>
                <p className="text-white/60 text-sm leading-relaxed italic">{liveTranscript}</p>
              </div>
            )}
          </div>
        )}

        {result && (
          <div className="space-y-8 animate-fadein">
            <div className="liquid-card overflow-hidden p-0">
              <div className="relative overflow-hidden">
                <div
                  className={`absolute inset-0 opacity-10 -z-10 blur-[100px] ${
                    level === 'RED' ? 'bg-danger-500' : level === 'YELLOW' ? 'bg-warn-500' : level === 'UNVERIFIED' ? 'bg-slate-500' : 'bg-safe-500'
                  }`}
                ></div>
                <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent"></div>

                <div className="flex flex-col items-center py-10 px-6">
                  <div
                    className={`inline-flex items-center gap-2.5 mb-8 px-5 py-2 rounded-full border ${
                      level === 'RED'
                        ? 'bg-danger-500/10 border-danger-500/20 text-danger-400'
                        : level === 'YELLOW'
                          ? 'bg-warn-500/10 border-warn-500/20 text-warn-400'
                          : level === 'UNVERIFIED'
                            ? 'bg-slate-500/10 border-slate-400/20 text-slate-300'
                            : 'bg-safe-500/10 border-safe-500/20 text-safe-400'
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full animate-pulse ${
                        level === 'RED'
                          ? 'bg-danger-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]'
                          : level === 'YELLOW'
                            ? 'bg-warn-400 shadow-[0_0_8px_rgba(250,204,21,0.5)]'
                            : level === 'UNVERIFIED'
                              ? 'bg-slate-400 shadow-[0_0_8px_rgba(148,163,184,0.5)]'
                              : 'bg-safe-400 shadow-[0_0_8px_rgba(74,222,128,0.5)]'
                      }`}
                    ></span>
                    <span className="text-xs font-black uppercase tracking-[0.2em]">{verdictLabel}</span>
                  </div>

                  <div className="relative w-36 h-36 mb-6">
                    <svg className="w-full h-full" viewBox="0 0 160 160" style={{ transform: 'rotate(-90deg)' }}>
                      <circle cx="80" cy="80" r="68" stroke="currentColor" strokeWidth="6" fill="transparent" className="text-white/5" />
                      <circle
                        cx="80" cy="80" r="68" stroke="currentColor" strokeWidth="6" fill="transparent"
                        strokeLinecap="round"
                        strokeDasharray={2 * Math.PI * 68}
                        strokeDashoffset={2 * Math.PI * 68 * (1 - score / 100)}
                        className={`transition-all duration-1000 ease-out ${level === 'RED' ? 'text-danger-500' : level === 'YELLOW' ? 'text-warn-400' : level === 'UNVERIFIED' ? 'text-slate-400' : 'text-safe-400'}`}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-5xl font-black text-white leading-none">{score}</span>
                      <span className="text-[9px] uppercase font-black text-white/35 tracking-[0.2em] mt-1.5">Điểm rủi ro</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-center gap-5 text-[11px] text-white/45 font-bold">
                    {asStr(result['language']) && (
                      <span className="flex items-center gap-1.5"><i className="bi bi-translate"></i><span>{asStr(result['language'])}</span></span>
                    )}
                    {typeof duration === 'number' && (
                      <span className="flex items-center gap-1.5"><i className="bi bi-clock"></i><span>{duration.toFixed(1)}s</span></span>
                    )}
                    {segments.length > 0 && (
                      <span className="flex items-center gap-1.5"><i className="bi bi-list-ol"></i><span>{segments.length} đoạn</span></span>
                    )}
                  </div>
                </div>
              </div>

              <div className="p-6 sm:p-8 space-y-8">
                <div className="space-y-3">
                  <h4 className="text-[10px] font-black text-brand2-400 uppercase tracking-[0.2em] flex items-center gap-2">
                    <i className="bi bi-chat-left-text"></i> Nội dung nhận diện
                  </h4>
                  {segments.length > 0 ? (
                    <div className="space-y-1.5 max-h-[400px] overflow-y-auto custom-scrollbar">
                      {segments.map((seg, idx) => (
                        <div key={idx} className="flex gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-colors group/seg">
                          <span className="text-[10px] font-mono text-brand2-400/40 whitespace-nowrap pt-0.5 shrink-0 group-hover/seg:text-brand2-400/70 transition-colors">
                            {formatTimestamp(seg.start)} →
                          </span>
                          <span className="text-white/70 text-sm leading-relaxed">{seg.text}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5">
                      <p className="text-white/60 text-sm leading-relaxed">{asStr(result['transcript']) || 'Không nhận diện được nội dung.'}</p>
                    </div>
                  )}
                </div>

                {asStr(result['transcript']) && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
                        <i className="bi bi-file-text"></i> Văn bản đầy đủ
                      </h4>
                      <button
                        type="button"
                        onClick={() => {
                          try {
                            void navigator.clipboard.writeText(asStr(result['transcript'])).then(() => showToast('Đã sao chép!', 'success'));
                          } catch {
                            showToast('Không thể sao chép.', 'error');
                          }
                        }}
                        className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-brand2-500/10 text-white/45 hover:text-brand2-400 border border-white/5 hover:border-brand2-500/20 text-[10px] font-black uppercase tracking-widest transition-all"
                      >
                        <i className="bi bi-copy mr-1"></i> Sao chép
                      </button>
                    </div>
                    <div className="p-5 rounded-2xl bg-black/30 border border-white/5 max-h-[200px] overflow-y-auto custom-scrollbar">
                      <p className="text-white/55 text-sm leading-relaxed font-mono whitespace-pre-wrap">{asStr(result['transcript'])}</p>
                    </div>
                  </div>
                )}

                <div className="space-y-3">
                  <h4 className="text-[10px] font-black text-brand2-400 uppercase tracking-[0.2em] flex items-center gap-2">
                    <i className="bi bi-shield-exclamation"></i> Phân tích AI
                  </h4>
                  <div className="p-5 rounded-2xl bg-brand2-500/[0.03] border border-brand2-500/10 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-brand2-500/5 blur-3xl rounded-full -mr-16 -mt-16"></div>
                    <MarkdownView html={renderMd(asStr(result['explanation']))} className="relative text-white/70 text-sm leading-relaxed" />
                  </div>
                </div>

                <TrustGuardrailPanel result={result} />

                {webSources.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
                      <i className="bi bi-globe2"></i> Nguồn tham khảo
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {webSources.map((src, idx) => (
                        <span key={idx} className="px-3 py-1.5 rounded-full bg-brand2-500/10 text-brand2-400 text-[10px] font-black border border-brand2-500/20 uppercase tracking-wide">
                          {src}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex flex-wrap gap-4">
              <button
                type="button"
                onClick={resetAll}
                className="bg-white/5 hover:bg-white/10 border border-white/10 px-8 py-3.5 rounded-2xl text-white font-black text-xs uppercase tracking-widest transition-all hover:scale-[1.02]"
              >
                <i className="bi bi-arrow-repeat mr-2"></i> Quét khác
              </button>
              <Link
                href="/report/"
                className="bg-danger-500/10 hover:bg-danger-500/20 border border-danger-500/20 px-8 py-3.5 rounded-2xl text-danger-400 font-black text-xs uppercase tracking-widest transition-all flex items-center gap-2 hover:scale-[1.02]"
              >
                <i className="bi bi-exclamation-triangle"></i> Báo cáo lừa đảo
              </Link>

            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="audio" />
    </div>
  );
}
