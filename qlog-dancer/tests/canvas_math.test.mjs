import assert from 'node:assert/strict';
import test from 'node:test';

import {
    canvasToPlotCoords,
    formatPlotCoordinate,
    interpolatePlotRange,
} from '../canvas-math.mjs';

test('full u64 axis precision is preserved for chart positions', () => {
    const max = (1n << 64n) - 1n;
    const min = max - 15n;
    assert.equal(interpolatePlotRange(min, max, 0), min);
    assert.equal(interpolatePlotRange(min, max, 1), max);
    assert.equal(interpolatePlotRange(min, max, 0.5), max - 7n);
    assert.equal(interpolatePlotRange(max, min, 0.5), max - 8n);

    const bounds = { left: 10, top: 20, width: 100, height: 100 };
    const axes = { x_min: min, x_max: max, y_min: 0n, y_max: 10n };
    assert.deepEqual(canvasToPlotCoords(60, 70, bounds, axes), {
        x: max - 7n,
        y: 5n,
    });
    assert.deepEqual(canvasToPlotCoords(10, 20, bounds, axes), {
        x: min,
        y: 10n,
    });
    assert.deepEqual(canvasToPlotCoords(110, 120, bounds, axes), {
        x: max,
        y: 0n,
    });
});

test('floating axes remain floating and tooltips format both numeric kinds', () => {
    const bounds = { left: 10, top: 20, width: 100, height: 100 };
    const axes = { x_min: 0.5, x_max: 10.5, y_min: 2, y_max: 12 };
    assert.deepEqual(canvasToPlotCoords(60, 70, bounds, axes), {
        x: 5.5,
        y: 7,
    });
    assert.equal(formatPlotCoordinate(5.55, 1), '5.5');
    assert.equal(formatPlotCoordinate((1n << 64n) - 1n), '18446744073709551615');
});

test('missing, degenerate and out-of-bounds charts produce no coordinates', () => {
    const bounds = { left: 0, top: 0, width: 100, height: 100 };
    const axes = { x_min: 0n, x_max: 10n, y_min: 0n, y_max: 10n };
    assert.equal(canvasToPlotCoords(0, 0, null, axes), null);
    assert.equal(canvasToPlotCoords(0, 0, bounds, null), null);
    assert.equal(canvasToPlotCoords(Number.NaN, 0, bounds, axes), null);
    assert.equal(canvasToPlotCoords(1000, 0, bounds, axes), null);
    assert.equal(canvasToPlotCoords(-1, 0, bounds, axes), null);
    assert.equal(canvasToPlotCoords(0, 0, { ...bounds, width: 0 }, axes), null);
    assert.equal(canvasToPlotCoords(0, 0, { ...bounds, height: -1 }, axes), null);
    assert.throws(() => interpolatePlotRange(0n, 1, 0.5), TypeError);
});
