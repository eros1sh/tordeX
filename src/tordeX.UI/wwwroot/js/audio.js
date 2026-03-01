/**
 * tordeX Audio Module — Voice message recording and playback.
 * Uses MediaRecorder API for recording and HTML5 Audio for playback.
 */
window.tordeXAudio = {
    _mediaRecorder: null,
    _audioChunks: [],
    _startTime: null,
    _timerInterval: null,
    _audioElements: {},

    /**
     * Start recording audio from microphone.
     * @param {DotNetObjectReference} dotNetRef - Blazor component reference
     */
    startRecording: async function (dotNetRef) {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
                ? 'audio/webm;codecs=opus'
                : 'audio/webm';

            this._mediaRecorder = new MediaRecorder(stream, { mimeType });
            this._audioChunks = [];
            this._startTime = Date.now();

            this._mediaRecorder.ondataavailable = (e) => {
                if (e.data.size > 0) this._audioChunks.push(e.data);
            };

            this._mediaRecorder.onstop = async () => {
                stream.getTracks().forEach(t => t.stop());
                if (this._timerInterval) {
                    clearInterval(this._timerInterval);
                    this._timerInterval = null;
                }

                if (this._audioChunks.length === 0) return;

                const blob = new Blob(this._audioChunks, { type: mimeType });
                const duration = (Date.now() - this._startTime) / 1000;

                // Convert to base64
                const reader = new FileReader();
                reader.onloadend = async () => {
                    const base64 = reader.result.split(',')[1];
                    await dotNetRef.invokeMethodAsync('OnRecordingComplete', base64, duration);
                };
                reader.readAsDataURL(blob);
            };

            this._mediaRecorder.start(250);

            // Timer for UI updates (elapsed seconds)
            this._timerInterval = setInterval(async () => {
                const elapsed = (Date.now() - this._startTime) / 1000;
                await dotNetRef.invokeMethodAsync('OnRecordingTick', elapsed);
            }, 200);

            return true;
        } catch (err) {
            console.error('Recording failed:', err);
            return false;
        }
    },

    /**
     * Stop recording and trigger OnRecordingComplete callback.
     */
    stopRecording: function () {
        if (this._timerInterval) {
            clearInterval(this._timerInterval);
            this._timerInterval = null;
        }
        if (this._mediaRecorder && this._mediaRecorder.state === 'recording') {
            this._mediaRecorder.stop();
        }
    },

    /**
     * Cancel recording without saving.
     */
    cancelRecording: function () {
        if (this._timerInterval) {
            clearInterval(this._timerInterval);
            this._timerInterval = null;
        }
        if (this._mediaRecorder) {
            if (this._mediaRecorder.state === 'recording') {
                this._mediaRecorder.stream.getTracks().forEach(t => t.stop());
                this._mediaRecorder.stop();
            }
            this._audioChunks = [];
            this._mediaRecorder = null;
        }
    },

    /**
     * Play an audio message from base64 data.
     * @param {string} messageId - Unique message ID for tracking
     * @param {string} base64Data - Base64-encoded audio data
     * @param {DotNetObjectReference} dotNetRef - For playback state callbacks
     */
    playAudio: function (messageId, base64Data, dotNetRef) {
        this.stopAudio(messageId);

        try {
            const bytes = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
            const blob = new Blob([bytes], { type: 'audio/webm' });
            const url = URL.createObjectURL(blob);
            const audio = new Audio(url);
            this._audioElements[messageId] = audio;

            audio.onended = async () => {
                URL.revokeObjectURL(url);
                delete this._audioElements[messageId];
                if (dotNetRef) {
                    await dotNetRef.invokeMethodAsync('OnPlaybackEnded', messageId);
                }
            };

            audio.play();
            return true;
        } catch (err) {
            console.error('Playback failed:', err);
            return false;
        }
    },

    /**
     * Stop playing a specific audio message.
     */
    stopAudio: function (messageId) {
        if (this._audioElements[messageId]) {
            this._audioElements[messageId].pause();
            this._audioElements[messageId].currentTime = 0;
            delete this._audioElements[messageId];
        }
    },

    /**
     * Check if microphone permission is available.
     */
    checkMicPermission: async function () {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            stream.getTracks().forEach(t => t.stop());
            return true;
        } catch {
            return false;
        }
    }
};

/**
 * tordeX DOM utilities — safe interop functions replacing eval() calls.
 */
window.tordeXDom = {
    /**
     * Scroll an element to the bottom.
     * @param {string} elementId - The DOM element ID to scroll
     */
    scrollToBottom: function (elementId) {
        const el = document.getElementById(elementId);
        if (el) {
            el.scrollTo(0, el.scrollHeight);
        }
    }
};
