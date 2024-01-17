import express from "express";
import session from "express-session";
import mongoose from "mongoose";
import MongoStore from "connect-mongo";
import { engine } from "express-handlebars";

import { cartRouter } from "./routes/carts.routes.js";
import { chatRouter } from "./routes/chat.routes.js";
import { productRouter } from "./routes/products.routes.js";
import viewsRouter from './routes/views.router.js'
import sessionRouter from './routes/session.routes.js'

import __dirname from "./utils.js";
import path from 'path'

const PORT = 8080;
const app = express();

const MONGO = 'mongodb+srv://pabloagusrivero:azqsxwdce01@cluster0.ypyomam.mongodb.net/ecommerce'

const connection = mongoose.connect(MONGO)

app.use(express.json());
app.use(express.urlencoded({extended:true}))
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
    store: new MongoStore({
        mongoUrl: MONGO,
        ttl:3600
    }),
    secret:"CoderSecret",
    resave:false,
    saveUninitialized:false
}))

app.engine("handlebars", engine())
app.set("views", __dirname + "/views")
app.set("view engine", "handlebars")

app.use('/', viewsRouter)
app.use('/api/sessions', sessionRouter)
app.use('/api/products', productRouter)
app.use('/api/carts', cartRouter)
app.use('/api/chat', chatRouter)

app.listen(PORT, ()=>{
    console.log(`Servidor funcionando en el puerto: ${PORT}`)
})
