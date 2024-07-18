const express = require('express')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express()
require('dotenv').config()
const cors = require('cors')
const port = process.env.PORT || 5000


// middleware

app.use(cors())
app.use(express.json())




const { MongoClient, ServerApiVersion,ObjectId } = require('mongodb');



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ckoz8fu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// const uri = "mongodb+srv://<username>:<password>@cluster0.ckoz8fu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const userCollection =client.db("mafDB").collection("user");
    app.get('/user',async(req, res)=>{
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    // Middleware to verify JWT
const auth = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};


//  register-----------------------------------------------------
    app.post('/register', async (req, res) => {
      const { name, pin, mobile, email, role } = req.body;

      if (!name || !pin || !mobile || !email || !role) {
        return res.status(400).json({ message: 'All fields are required' });
      }
    
      if (!/^\d{5}$/.test(pin)) {
        return res.status(400).json({ message: 'PIN must be a 5-digit number' });
      }
    
      const hashedPin = await bcrypt.hash(pin, 10);
    
      try {
        const newUser = {
          name,
          pin: hashedPin,
          mobile,
          email,
          status: 'pending',
          role,
        };
    
        await userCollection.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully' });
      } catch (error) {
        res.status(500).json({ message: 'Error registering user' });
      }
      
      
    });


    // User Login Route
app.post('/login', async (req, res) => {
  const { email, pin } = req.body;
  
  if (!email || !pin) {
    return res.status(400).json({ message: 'Email and PIN are required' });
  }

    

    try {
      const user = await userCollection.findOne({ email });
     
      if (!user) {
        return res.status(400).json({ message: 'Invalid email or PIN' });
      }
      
      const isMatch = await bcrypt.compare(pin, user.pin);
     
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid email or PIN' });
      }
     
      const token = jwt.sign({ id: user._id }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '1h',
      });
      // console.log("check--",email,pin,user,isMatch,token);
      res.json({ token });
    } catch (error) {
      res.status(500).json({ message: 'Error logging in' });
    }






});

// Middleware to verify JWT


// DashBord-------------------------------------------------------
app.get('/dashboard', async (req, res) => {

  try {
    const user = await userCollection.findOne({ _id: ObjectId(req.user.id) });

    console.log(req);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Welcome to the dashboard', user });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching dashboard data' });
  }
  
});


    




    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);








app.get('/', (req, res) => {
  res.send('Hello from SurveyApp Server Server..')
})

app.listen(port, () => {
  console.log(`SurveyApp Server is running on port ${port}`)
})