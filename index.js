import express from "express";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import { ObjectId } from "mongodb";
import cors from "cors";  
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

const PORT = process.env.PORT;

app.use(cors());

app.use(express.json());

const MONGO_URL = process.env.MONGO_URL;

async function createConnection(){
    const client =  new MongoClient(MONGO_URL); 
    await client.connect();  
    console.log("Mongodb Connected");
    return client;
}
const client = await createConnection();


const auth = (request, response, next) => {
	try{
		const token = request.header("x-auth-token");
		console.log("token", token);
		jwt.verify(token, process.env.SECRET_KEY);
		next();
	}catch (err) {
response.status(401).send({error: err.message});
	}
};

app.get("/",(request,response)=>{
    response.send("hello world");
});

    app.get("/saladrecipe", async (request,response)=>{
        const recipeblog = await client 
        .db("b28wd")
        .collection("saladblog")
        .find({})
        .toArray();
        response.send(recipeblog);
    });
    
    app.get("/saladrecipe/:id", async (request,response)=>{
        console.log(request.params);
        const {id} = request.params;
        const blogresult = await getSaladBlogById(id);
        console.log(blogresult);
    
        blogresult? response.send(blogresult) : response.status(404).send({message:"no matching movie found"});
    });
    
    app.post("/saladrecipe", async (request,response)=>{
        const data = request.body;
        const result = await client.db("b28wd").collection("saladblog").insertOne(data);
        response.send(result);
        });

        app.delete("/saladrecipe/:id", auth, async (request,response)=>{
            console.log(request.params);
            const {id} = request.params;
            const result = await deleteSaladBlogById(id)
            console.log(result);
        
            result.deletedCount>0? response.send(result) : response.status(404).send({message:"no matching movie found"});
        });

        app.put("/saladrecipe/:id",async (request,response)=>{
            console.log(request.params);
            const {id} = request.params;
            const data = request.body;
            const result = await editSaladBlogById(id, data);
            const movie = await getSaladBlogById(id);
            console.log(result);
            response.send(movie);
        });
        
        async function editSaladBlogById(id, data) {
            return await client
                .db("b28wd")
                .collection("saladblog")
                .updateOne({ _id: ObjectId(id) }, { $set: data });
        }
    
        async function getSaladBlogById(id) {
            return await client
                .db("b28wd")
                .collection("saladblog")
                .findOne({ _id: ObjectId(id) });
        }

        async function deleteSaladBlogById(id) {
            return await client
                .db("b28wd")
                .collection("saladblog")
                .deleteOne({ _id: ObjectId(id) });
        }

        async function createUser(data) {
            return await client.db("b28wd").collection("projectpassword").insertOne(data);
        }
        
        async function getUserByName(email) {
            return await client
                .db("b28wd")
                .collection("projectpassword")
                .findOne({ email: email });
        }
        
        
        
        async function genPassword(password){
            const NO_OF_ROUNDS = 10;
            const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
            console.log(salt);
            const hashedPassword = await bcrypt.hash(password, salt);
            console.log(hashedPassword);
            return hashedPassword;
        }
        
        
        app.post("/signup", async (request,response)=>{
            const {email, password} = request.body;
            const userFromDB = await getUserByName(email);
        console.log(userFromDB);
        
        if(userFromDB){
            response.send({message: "email already exists"});
            // response.status(400).send({message: "email already exists"});
            return;
        }
        
        if(password.length < 8){
            response.send({message: "password must be longer"});
            // response.status(400).send({message: "password must be longer"});
            return;
        }
        
        
            const hashedPassword = await genPassword(password); 
            const result = await createUser({ email, password:hashedPassword });
            response.send(result);   
            });
        
        app.post("/login", async (request,response)=>{
            const {email, password} = request.body;
            const userFromDB = await getUserByName(email);
        
            if(!userFromDB){
                response.send({message: "Invalid Credentials"});
                // response.status(401).send({message: "Invalid Credentials"});
                return;
            }
        
            const storedPassword = userFromDB.password;
            console.log(storedPassword);
        
            const isPasswordMatch = await bcrypt.compare(password, storedPassword);
        
            console.log(isPasswordMatch);
            console.log(userFromDB);
        
            if (isPasswordMatch) {
                const token = jwt.sign({id: userFromDB._id}, process.env.SECRET_KEY);
                response.send({message: "sucessful login", token: token});
            }else{
                response.send({message: "Invalid Credentials"});
                // response.status(401).send({message: "Invalid Credentials"});
            }
        
            
        });
    

app.listen(PORT,()=>console.log("App is started in", PORT));