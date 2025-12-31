import mongoose from 'mongoose';

const storeSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true 
  },
  owner: { 
    type: String, 
    default: "" 
  },
  email: { 
    type: String, 
    unique: true 
  },
  contact: { 
    type: String,
    unique: true,
    required: true 
  },
  // Location data
  lat: { 
    type: Number, 
    default: 0.0 
  },
  long: { 
    type: Number, 
    default: 0.0 
  },
  // Image URL/Path
  storeImage: { 
    type: String, 
    default: "" 
  },
  // Technician specific logic
  isTechnician: { 
    type: Boolean, 
    default: false 
  },
  technicianId: { 
    type: String, 
    // Only required if isTechnician is true (optional validation logic)
    required: function() { return this.isTechnician; }
  },
  technicianName: {
    type: String,
    default: ""
  },
  product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Product",
    },
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true 
  }
}, { timestamps: true });

export const Store = mongoose.model('Store', storeSchema);