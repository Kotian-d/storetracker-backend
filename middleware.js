import jwt from 'jsonwebtoken';

export const authenticateToken = (req, res, next) => {
  // 1. Get token from header (Format: "Bearer <token>")
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // 2. Check if token exists
  if (!token) {
    return res.status(401).json({ 
      status: 'error', 
      message: 'Access Denied: No Token Provided' 
    });
  }

  try {
    // 3. Verify token using your Secret Key
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    
    // 4. Attach user info to the request (so routes can use req.user.id)
    req.user = verified;
    
    // 5. Move to the next function/route
    next();
  } catch (error) {
    res.status(403).json({ 
      status: 'error', 
      message: 'Invalid or Expired Token' 
    });
  }
};