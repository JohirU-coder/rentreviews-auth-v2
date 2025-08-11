# RentReviews Authentication Service V2

🔒 **Production-ready authentication service with hardcoded CORS configuration**

## Features

- ✅ JWT-based authentication
- ✅ Hardcoded CORS origins (no environment variable dependencies)
- ✅ Rate limiting protection
- ✅ bcrypt password hashing
- ✅ Input validation with Joi
- ✅ Enterprise-grade security headers
- ✅ PostgreSQL database integration
- ✅ Account lockout protection

## API Endpoints

- `GET /health` - Health check
- `POST /register` - User registration
- `POST /login` - User authentication
- `GET /profile` - Get user profile (protected)
- `POST /refresh` - Refresh JWT token (protected)
- `GET /migrate` - Database migration utility
- `GET /check-schema` - Database schema inspection

## Environment Variables Required

```
NODE_ENV=production
DATABASE_URL=your_postgresql_connection_string
JWT_SECRET=your_super_secret_jwt_key
SENDGRID_API_KEY=your_sendgrid_key (optional)
FROM_EMAIL=your_email@domain.com (optional)
```

## CORS Configuration

This service uses **hardcoded CORS origins** for reliability:
- `http://localhost:5500`
- `http://127.0.0.1:5500`
- `http://localhost:3000`
- `http://127.0.0.1:3000`

No `FRONTEND_URL` environment variable needed!

## Deployment

1. Deploy to Railway
2. Set required environment variables
3. Service will auto-start on port 8080
4. Database tables will be created automatically

## Security Features

- Password hashing with bcrypt (12 salt rounds)
- JWT tokens with 7-day expiration
- Rate limiting (5 auth attempts per 15 minutes)
- Account lockout after 5 failed attempts
- Input sanitization and validation
- Helmet.js security headers

## Version

**2.1.0** - Hardcoded CORS, Production Ready