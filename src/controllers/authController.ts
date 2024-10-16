import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User';

// Register user
export const registerUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const { firstName, email, password } = req.body;

  if (!firstName || !email || !password) {
    res.status(400).json({ message: 'All fields are required' });
    return;
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      res.status(400).json({ message: 'User already exists' });
      return;
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({ firstName, email, password: hashedPassword });

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }

    const token = jwt.sign({ id: user._id, firstName: user.firstName }, jwtSecret, {
      expiresIn: '1h',
    });

    // Return both the token and the user's first name
    res.status(201).json({ token, firstName: user.firstName });
  } catch (error) {
    console.error('Error during registration:', (error as any).message); 
    res.status(500).json({ message: 'Server Error', error: (error as any).message });
  }
};

// Login user
export const loginUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: 'All fields are required' });
    return;
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(400).json({ message: 'Invalid credentials' });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.status(400).json({ message: 'Invalid credentials' });
      return;
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }

    const token = jwt.sign({ id: user._id, firstName: user.firstName }, jwtSecret, {
      expiresIn: '1h',
    });

    // Return both the token and the user's first name
    res.status(200).json({ token, firstName: user.firstName });
  } catch (error) {
    console.error('Error during login:', (error as any).message); 
    res.status(500).json({ message: 'Server Error', error: (error as any).message });
  }
};
