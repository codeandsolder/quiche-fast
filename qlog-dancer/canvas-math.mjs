// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Interpolate pixel-resolution fractions while preserving exact 64-bit qlog
// counter endpoints. A 53-bit fixed-point fraction exceeds pixel precision.
export function interpolatePlotRange(min, max, fraction) {
    if (typeof min === 'bigint' || typeof max === 'bigint') {
        if (typeof min !== 'bigint' || typeof max !== 'bigint') {
            throw new TypeError('Both endpoints of a plot axis must have the same numeric type');
        }
        const denominator = 1n << 53n;
        const numerator = BigInt(Math.round(fraction * Number(denominator)));
        const scaled = (max - min) * numerator;
        const half = denominator / 2n;
        const offset = scaled >= 0n
            ? (scaled + half) / denominator
            : (scaled - half) / denominator;
        return min + offset;
    }
    return min + fraction * (max - min);
}

export function formatPlotCoordinate(value, decimals = 0) {
    return typeof value === 'bigint' ? value.toString() : value.toFixed(decimals);
}

export function canvasToPlotCoords(canvasX, canvasY, chartBounds, plotRanges) {
    if (!chartBounds || !plotRanges ||
        !Number.isFinite(canvasX) || !Number.isFinite(canvasY) ||
        !Number.isFinite(chartBounds.width) || !Number.isFinite(chartBounds.height) ||
        chartBounds.width <= 0 || chartBounds.height <= 0) {
        return null;
    }
    const plotPixelX = canvasX - chartBounds.left;
    const plotPixelY = canvasY - chartBounds.top;
    if (plotPixelX < 0 || plotPixelX > chartBounds.width ||
        plotPixelY < 0 || plotPixelY > chartBounds.height) {
        return null;
    }

    const normalizedX = plotPixelX / chartBounds.width;
    const normalizedY = plotPixelY / chartBounds.height;
    return {
        x: interpolatePlotRange(plotRanges.x_min, plotRanges.x_max, normalizedX),
        y: interpolatePlotRange(plotRanges.y_min, plotRanges.y_max, 1 - normalizedY),
    };
}
