# Third-Party Licenses

`lssudo` statically links a modified copy of **sudo-rs** into the shipped
binary. sudo-rs is distributed under a dual Apache-2.0 / MIT license; we
distribute it under the **MIT** terms, reproduced below.

- Upstream: <https://github.com/trifectatechfoundation/sudo-rs>
- Pinned ref: `v0.2.15`
- Modifications: see `sudo-rs.patch` in this directory. The patch widens
  the visibility of several internal modules and stubs out one FFI call
  to `pam_strerror` so that lssudo can be built fully static without
  linking against `libpam`.

---

## sudo-rs — MIT License

Copyright (c) 2022-2026 Trifecta Tech Foundation and contributors
Copyright (c) 1994-1996, 1998-2024 Todd C. Miller

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
