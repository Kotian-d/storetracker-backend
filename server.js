import "dotenv/config";
import express, { json } from "express";
import cors from "cors";
import multer, { diskStorage } from "multer";
import { extname } from "path";
import xlsx from "xlsx";
import fs from "fs";
import { Store } from "./models/store_schema.js"; // Import the schema we just made
import connectDB from "./db.js"; // Import the database connection function
import { Product } from "./models/product_schema.js"; // Import Product schema
import bcrypt from "bcryptjs";
import { User } from "./models/user_schema.js";
import jwt from "jsonwebtoken";
import { authenticateToken } from "./middleware.js";

// --- Initialize Express App ---
const app = express();
const cache = new Map();
// --- Middleware ---
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);
app.options(/(.*)/, cors());
app.use(json());
// Serve the 'uploads' folder statically so the Flutter app can view images
app.use("/uploads", express.static("uploads"));

// --- Image Upload Configuration (Multer) ---
const storage = diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Images will be saved in an 'uploads' folder
  },
  filename: (req, file, cb) => {
    // Save as: storeid-timestamp.jpg
    cb(null, file.fieldname + "-" + Date.now() + extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

// ================= API ROUTES =================

// 1. Get All Stores
app.get("/api/store", authenticateToken, async (req, res) => {
  try {
    // The .find({}) method with an empty object retrieves ALL documents
    // from the 'Store' collection.
    if (req.user.roles.includes("admin")) {
      const stores = await Store.find({}).populate(["product", "user"]);
      return res.status(200).json(stores);
    }
    const stores = await Store.find({ user: req.user.userId }).populate([
      "product",
      "user",
    ]);

    // Respond with a 200 OK status and the array of stores in JSON format.
    res.status(200).json(stores);
  } catch (error) {
    // If a database or server error occurs, respond with a 500 Internal Server Error.
    console.error("Error fetching all stores:", error);
    res.status(500).json({
      message: "Failed to retrieve stores from the database.",
      error: error.message,
    });
  }
});

// 2. Create a New Store
app.post(
  "/api/store",
  authenticateToken,
  upload.single("storeImage"),
  async (req, res) => {
    try {
      // If an image was uploaded, get the path, otherwise empty string
      const imagePath = req.file ? `/uploads/${req.file.filename}` : "";

      const newStore = new Store({
        name: req.body.name,
        owner: req.body.owner,
        email: req.body.email,
        contact: req.body.contact,
        lat: req.body.lat,
        long: req.body.long,
        storeImage: imagePath,
        isTechnician: req.body.isTechnician === "true", // Parse string to boolean
        technicianId: req.body.technicianId,
        product: req.body.product,
        user: req.body.user,
      });

      const savedStore = await newStore.save();
      res.status(201).json(savedStore);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// 3. Get Store Data by ID
app.get("/api/store/:id", authenticateToken, async (req, res) => {
  try {
    const store = await Store.findById(req.params.id);
    if (!store) return res.status(404).json({ message: "Store not found" });
    res.json(store);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. Update Location (Lat/Long)
app.put("/api/store/:id/location", authenticateToken, async (req, res) => {
  try {
    const { lat, long, user, product, owner, email, contact } = req.body;

    if (req.user.roles !== "admin" && req.user.userId !== user) {
      return res.status(403).json({
        message: "Forbidden: You don't have permission to update this store.",
      });
    }

    if (req.user.roles !== "admin") {
      const updatedStore = await Store.findByIdAndUpdate(
        req.params.id,
        { lat, long },
        { new: true } // Return the updated document
      );
      return res.json(updatedStore);
    }

    const updatedStore = await Store.findByIdAndUpdate(
      req.params.id,
      { lat, long, user, product, owner, email, contact },
      { new: true } // Return the updated document
    );

    return res.json(updatedStore);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. Update Store Image
app.post(
  "/api/store/:id/image",
  authenticateToken,
  upload.single("storeImage"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No image file provided" });
      }

      const imagePath = `/uploads/${req.file.filename}`;

      const updatedStore = await Store.findByIdAndUpdate(
        req.params.id,
        { storeImage: imagePath },
        { new: true }
      );

      // Return the full URL so Flutter can display it immediately
      // Ideally, prepend your server domain here (e.g., http://10.0.2.2:3000...)
      res.json({
        imageUrl: imagePath,
        store: updatedStore,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// 6. Delete a Store
app.delete("/api/store/:id", authenticateToken, async (req, res) => {
  try {
    await Store.findByIdAndDelete(req.params.id);
    return res.status(200).json({ message: "Store deleted successfuly" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. Endpoint to Upload Store Data from Excel
app.post(
  "/api/store/upload-excel",
  authenticateToken,
  upload.single("excelFile"),
  async (req, res) => {
    const filePath = req.file ? req.file.path : null;
    const productId = req.body.product;
    const userId = req.body.user;
    console.log("Excel file path:", filePath);

    if (!filePath) {
      return res.status(400).json({ message: "No Excel file uploaded." });
    }

    try {
      // 1. Read the Excel File
      const workbook = xlsx.readFile(filePath);

      // Assuming the data is in the first sheet (Sheet1)
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];

      // Convert the sheet data to an array of JSON objects
      const data = xlsx.utils.sheet_to_json(worksheet);

      const storesToInsert = [];

      // 2. Map Excel Columns to Mongoose Schema Fields
      for (const row of data) {
        // **CRITICAL STEP:** Map your Excel column headers (e.g., "Store Name")
        // to the Mongoose schema fields (e.g., 'name').
        storesToInsert.push({
          name: row["Store Name"] || row["name"],
          owner: row["Owner Name"] || row["owner"],
          email: row["Email Address"] || row["email"],
          contact: row["Contact Number"] || row["contact"],
          lat: parseFloat(row["Latitude"] || 0.0),
          long: parseFloat(row["Longitude"] || 0.0),
          // Assume storeImage, isTechnician, technicianId are optional or defaults
          isTechnician: String(row["Is Technician"]).toLowerCase(),
          technicianId: row["Technician ID"] || "",
          technicianName: row["Technician Name"] || "",
          product: productId,
          user: userId,
        });
      }

      // 3. Bulk Insert into MongoDB
      // Mongoose insertMany is highly efficient for bulk operations
      const result = await Store.insertMany(storesToInsert, { ordered: false });

      // 4. Respond with success
      res.status(200).json({
        message: `${result.length} stores successfully imported.`,
        importedCount: result.length,
        errors: result.errors, // errors will only be available if using {ordered: false}
      });
    } catch (error) {
      console.error("Error during bulk import:", error);
      res.status(500).json({
        message: "Failed to process and import Excel data.",
        error: error.message,
      });
    } finally {
      // 5. Clean Up: Delete the temporary file regardless of success or failure
      if (filePath) {
        fs.unlink(filePath, (err) => {
          if (err) console.error("Error deleting temp file:", err);
        });
      }
    }
  }
);

//get products
app.get("/api/products", authenticateToken, async (req, res) => {
  try {
    const products = await Product.find({});
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/products", authenticateToken, async (req, res) => {
  try {
    const newProduct = new Product({
      name: req.body.name,
    });
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

//get Users
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}).select("_id username");
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/geocode", authenticateToken, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing q" });

  if (cache.has(q)) {
    return res.json(cache.get(q));
  }
  /*
  const url = `https://nominatim.openstreetmap.org/search?` +
    `q=${encodeURIComponent(q)}&format=json&limit=1`;
*/
  const url =
    `https://api.geoapify.com/v1/geocode/autocomplete?` +
    `text=${encodeURIComponent(q)}&api_key=${process.env.GEOAPIFY_API_KEY}`;
  try {
    const resp = await fetch(url, {
      headers: {
        "Accept-Language": "en",
        "User-Agent": "StoreTracker/1.0 (storemanagement-frontend@vercel.app)",
        Referer: "https://storemanagement-frontend@vercel.app",
      },
    });

    if (!resp.ok) {
      const body = await resp.text();
      console.error("Nominatim error", resp.status, body);
      return res.status(resp.status).send(body);
    }

    const data = await resp.json();
    cache.set(q, data);
    res.json(data);
  } catch (e) {
    console.error("Geocode proxy error", e);
    res.status(500).json({ error: "Upstream error" });
  }
});

app.get("/api/geocoding/:query", authenticateToken, async (req, res) => {
  const query = req.params.query;
  const uri = `https://api.maptiler.com/geocoding/${query}.json?key=${process.env.MAP_TILER_KEY}`;

  try {
    const response = await fetch(uri);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Geocoding error:", error);
    res.status(500).json({ error: "Failed to fetch geocoding data" });
  }
});

app.post("/api/matrix", authenticateToken, async (req, res) => {
  const body = req.body;

  try {
    const response = await fetch(
      "https://api.openrouteservice.org/v2/matrix/driving-car",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: process.env.ORS_API_KEY,
        },
        body: JSON.stringify(body),
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("matrix error:", error);
    res.status(500).json({ error: "Failed to fetch distance matrix data" });
  }
});

app.post("/api/getdirections", authenticateToken, async (req, res) => {
  const { fromLat, fromLon, toLat, toLon } = req.body;

  if (!fromLat || !fromLon || !toLat || !toLon) {
    return res
      .status(400)
      .json({ message: "Missing required query parameters." });
  }

  const body = {
    coordinates: [
      [fromLon, fromLat],
      [toLon, toLat],
    ],
  };

  const response = await fetch(
    "https://api.openrouteservice.org/v2/directions/driving-car/geojson",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: process.env.ORS_API_KEY,
      },
      body: JSON.stringify(body),
    }
  );

  if (!response.ok) {
    throw new Error("ORS routing error");
  }

  const data = await response.json();

  return res.status(200).json(data);
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("Login attempt for user:", username, password);

  if (!username || !password) {
    return res.status(400).json({
      status: "error",
      message: "Username and password are required.",
    });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res
        .status(401)
        .json({ status: "error", message: "Invalid username or password." });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      return res
        .status(401)
        .json({ status: "error", message: "Invalid username or password." });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.roles },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.status(200).json({
      success: true,
      token: token,
      user: { role: user.roles, username: user.username },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error." });
  }
});

app.get("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("roles username");
    res.json({ user });
  } catch (error) {
    console.error("Verify error:", error);
    res.status(500).json({ error: "Failed to verify user" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: "Password must be at least 6 characters long." });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: "Username already exists." });
  }

  const hashedPassword = bcrypt.hashSync(password, 10); // TODO: Hash the password before storing

  await User.create({
    username,
    password: hashedPassword,
  });

  return res.status(201).json({ message: "User registered successfully" });
});

app.get("/run", async (req, res) => {
  const result = await Store.find({ product: "693f80575bbfac018266a339" });
  result.map(
    async (store) =>
      await Store.findByIdAndUpdate(store._id, {
        user: "694e6b6ae44e2133a9b2be68",
      })
  );
  res.json(result);
});

// --- Start Server ---
const startServer = async () => {
  await connectDB();

  // Add app middlewares, routes here

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
};

startServer();
