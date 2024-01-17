import ProductModel from "../models/ProductsModel.js";

class ProductManagerDB {
    getProducts = async (options, query) => {
        const filter = query ? { category: query.category, status: query.status } : {};

        const products = await ProductModel.paginate(filter, options)

        const result = {
            status: "success",
            payload: products.docs,
            totalPages: products.totalPages,
            prevPage: products.prevPage,
            nextPage: products.nextPage,
            hasPrevPage: products.hasPrevPage,
            hasNextPage: products.hasNextPage,
            prevLink: products.hasPrevPage ? `${options.baseUrl}?page=${products.prevPage}` : null,
            nextLink: products.hasNextPage ? `${options.baseUrl}?page=${products.nextPage}` : null,
        };

        return result;
    }
    getProductById = async (pid) => {
        try {
            const product = await ProductModel.findOne({ _id: pid })

            if (!product) {
                return {
                    status: "error",
                    msg: `Producto con el id ${pid} no fue encontrado`
                };
            }

            return {
                status: "success",
                msg: product
            };
        } catch(error) {
            console.log(error);
            return {
                status: "error",
                msg: "Error interno en el servidor"
            }
        }
    }

    createProduct = async (newProduct) => {
        try {
            const createdProduct = await ProductModel.create(newProduct)

            return {
                status: "success",
                msg: "Producto creado exitosamente",
                product: createdProduct
            }
        } catch (error) {
            console.log(error)
            return {
                status: "error",
                msg: "Error al crear el producto"
            }
        }
    }

    deleteProduct = async (pid) => {
        try {
            const deletedProduct = await ProductModel.findByIdAndDelete(pid)

            if (!deletedProduct) {
                return {
                    status: "error",
                    msg: `No se encontro el producto con ID: ${pid}`
                }
            }

            return {
                status: "success",
                msg: `El producto con ID ${pid} fue eliminado exitosamente`,
                product: deletedProduct
            }
        } catch (error) {
            console.log(error)
            return {
                status: "error",
                msg: `Error al eliminar el producto con ID ${pid}`
            }
        }
    }
}

export default ProductManagerDB