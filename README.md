# JWT Decoder

A simple, minimalist JWT (JSON Web Token) decoder with a clean black and white design.

## Features

- **Simple Design**: Clean black and white interface with no gradients, box shadows, or hover effects
- **Real-time Decoding**: Automatically decodes JWT tokens as you type
- **Local Processing**: All decoding happens in your browser - no data sent to servers
- **Error Handling**: Clear error messages for invalid tokens
- **Responsive Layout**: Works on desktop and mobile devices

## Usage

1. Open `index.html` in a web browser
2. Paste a JWT token into the textarea
3. The decoded header, payload, and signature will appear automatically

### Running Locally

You can serve the application using any HTTP server. For example:

```bash
# Using Python 3
python3 -m http.server 8000

# Using Python 2
python -m SimpleHTTPServer 8000

# Using Node.js
npx http-server
```

Then open your browser to `http://localhost:8000`

## How JWT Decoding Works

A JWT token consists of three parts separated by dots (`.`):
1. **Header**: Contains metadata about the token (algorithm, type)
2. **Payload**: Contains the claims/data
3. **Signature**: Used to verify the token's authenticity

This decoder extracts and displays the header and payload. The signature is displayed but not verified (verification requires the secret key).

## Example JWT

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## Design Philosophy

This project follows a minimalist approach:
- Pure black (#000000) and white (#ffffff) color scheme
- No box shadows
- No hover effects
- No gradients
- Simple, clean borders
- Focus on functionality over aesthetics

## Files

- `index.html` - Main HTML structure
- `style.css` - Black and white styling
- `script.js` - JWT decoding logic

## License

Open source and free to use.