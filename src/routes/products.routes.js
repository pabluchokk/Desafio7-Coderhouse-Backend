import { Router } from "express";
import ProductManagerDB from "../dao/dbManagers/ProductManagerDB.js";

const path = "products.json";
const router = Router();
const productManagerDB = new ProductManagerDB(path);

router.get("/", async (req, res)=>{
    try {
        const { limit, page, sort, query } = req.query

        const options = {
            limit: limit ?? 10,
            page: page ?? 1,
            sort: sort ? { price: sort === "asc" ? 1 : -1 } : undefined,
            lean:true
        }

        const products = await productManagerDB.getProducts(options)

        if(products.hasPrevPage){
            products.prevLink = `${req.protocol}://${req.get("host")}${req.baseUrl}?page=${products.prevPage}`
        }
        if(products.hasNextPage){
            products.nextLink = `${req.protocol}://${req.get("host")}${req.baseUrl}?page=${products.nextPage}`
        }
    
        res.render("products", { productos: products.docs })
    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: "error",
            msg: "Error interno del servidor"
        })
    }
})

router.get("/:pid", async (req, res)=>{
    const pid = req.params.pid

    res.send({
        status:"success",
        msg:`Ruta GET ID PRODUCTS con el ID: ${pid}`
    })
})

router.post("/", async (req, res)=>{
    const {
        title,
        description,
        code,
        price,
        stock,
        category,
        thumbnails
    } = req.body

    if (!title || !description || !code || !price || !stock || !category) {
        return res.status(400).json({
        status: "error",
        msg: "Todos los campos son obligatorios, excepto thumbnails.",
        });
    }
const product = {
    title,
    description,
    code,
    price: Number(price),
    status: true,
    stock: Number(stock),
    category,
    thumbnails: thumbnails || [],
}

    const products = await productManagerDB.createProduct(product)

    res.send({
        status:"success",
        msg:"Producto creado",
        productos: products,
    })
})

router.put("/:pid", async (req, res)=>{
    const pid = req.params.pid;

    const products = await productManagerDB.getProducts();
    const existingProductIndex = products.findIndex(
        (product) => product.id == pid
    )

    const updatedProduct = {
        ...products[existingProductIndex],
        ...req.body,
        id: pid
    }

    products[existingProductIndex] = updatedProduct;

    await productManagerDB.createProduct(products)

    res.send({
        status: "success",
        msg: `Producto con ID ${pid} actualizado`,
        producto: updatedProduct
    })
})

router.delete("/:pid", async (req, res)=>{
    const pid = req.params.pid;
    const products = await productManagerDB.getProducts()
    const existingProductIndex = products.findIndex(
        (product) => product.id == pid
    )
    products.splice(existingProductIndex, 1);

    await productManagerDB.createProduct(products)

    res.send({
        status: "success",
        msg: `Producto con ID ${pid} eliminado`
    })
})

export {router as productRouter}