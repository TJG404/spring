import { ProductList } from "../components/product/ProductList.jsx";

export function Home() {
    return (
        <div className="content">
            <div className="banner">
                <h3>Shop with US</h3>
                <p>Best products, High Quality</p>
            </div>
            <ProductList />
        </div>
    );
}