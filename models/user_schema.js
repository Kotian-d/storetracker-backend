import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: true 
    },
    username: { 
        type: String, 
        required: true,
        unique: true 
    },
    password: {
        type: String,
        required: true
    },
    roles: { 
        type: String,
        default: "user",
        enum: ["user", "admin"]
    },
}, { timestamps: true });   

export const User = mongoose.model('User', userSchema);