import { Router } from "express";
import CartManagerDB from "../dao/dbManagers/CartManagerDB.js";

const router = Router();
const cartManagerDB = new CartManagerDB();

router.get("/", async (req, res)=>{

const carts = await cartManagerDB.getCarts()

    res.send({
        status:"success",
        carritos: carts
    })
})

router.get("/:cid", async (req, res)=>{
    try {
        const cid = req.params.cid;
        const carts = await cartManagerDB.getCarts();
        const targetCart = carts.find((cart) => cart.id === cid)

        res.render("cart", { cart: targetCart })
    } catch(error) {
        console.log(error)
        res.status(500).send({
            status: "error",
            msg:"Error interno del servidor."
        })
    }
})

router.post("/:cid/product/:pid", async (req, res)=>{
    const cid = req.params.cid
    const pid = req.params.pid
    const quantity = req.params.quantity
    const cart = await cartManagerDB.addProdInCart(pid, cid, quantity)

    res.send({
        status:"success",
        msg: cart
    })
})

router.post("/", async (req, res)=>{
    const carts = await cartManagerDB.getCarts()
    res.send({
        status: "success",
        msg: carts
    })
})

router.put("/:cid", async (req, res)=>{
    try {
        const cid = req.params.cid;
        const { products } = req.body;

        const cart = await cartManagerDB.updateCart(cid, products);

        res.send({
            status: "success",
            msg: `Carrito con ID ${cid} actualizado con exito`,
            cart: cart
        })
    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "error",
            msg: "Error interno del servidor"
        })
    }
})

router.put("/:cid/products/:pid", async (req, res) => {
    try {
        const cid = req.params.cid;
        const pid = req.params.pid;
        const { quantity } = req.body

        const cart = await cartManagerDB.updateProductQuantity(cid, pid, quantity)

        res.send({
            status: "success",
            msg: `Cantidad de producto con ID ${pid} actualizada en el carrito con ID ${cid}`,
            cart: cart
        })
    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "error",
            msg: "Error interno del servidor"
        })
    }
})

router.delete("/:cid", async (req, res)=>{
    try {
        const cid = req.params.cid;

        const result = await cartManagerDB.deleteCart(cid)

        if(result.status === "error") {
            return res.status(404).send(result)
        }

        res.send({
            status: "success",
            msg:`Carrito con ID ${cid} eliminado con exito`
        })
    } catch(error) {
        console.log(error)
        res.status(500).send({
            status: "error",
            msg:"Error interno del servidor"
        })
    }
})

router.delete("/:cid/products/:pid", async (req, res) => {
    try {
        const cid = req.params.cid;
        const pid = req.params.pid;

        const cart = await cartManagerDB.removeProductFromCart(cid, pid)

        res.send({
            status: "success",
            msg: `Producto con ID ${pid} fue eliminado del carrito con ID ${cid}`,
            cart: cart
        });
    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "error",
            msg: "Error interno del servidor"
        })
    }
})

export {router as cartRouter}