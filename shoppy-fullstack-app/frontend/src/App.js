import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './pages/Layout.jsx';
import { Products } from './pages/Products.jsx';
import { Home } from './pages/Home.jsx';
import { Login } from './pages/Login.jsx';
import { Signup } from './pages/Signup.jsx';
import { ProductDetail } from './pages/ProductDetail.jsx';
import { Cart } from './pages/Cart.jsx';
import { CheckoutInfo } from './pages/CheckoutInfo.jsx';
import { Support } from './pages/Support.jsx';
import { CartProvider } from './context/CartContext.js';
import { AuthProvider } from './context/AuthContext.js';
import { ProductProvider } from './context/ProductContext.js';
import { ProectedPageRoute } from './pages/ProectedPageRoute.js';
import { PayResult } from './pages/PayResult.jsx';

import './styles/cgvSignup.css';
import './styles/cgv.css';
import './styles/commons.css';
import './styles/shoppy.css';

import { useEffect } from 'react';
import { createCsrfToken } from './feature/auth/manageCsrfToken.js';

export default function App() {
    useEffect(() => {
        createCsrfToken();
    }, []);

  return (
    <AuthProvider>
    <ProductProvider>
    <CartProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Home/>} />
          <Route path="/all" element={<Products/>} />
          <Route path="/login" element={<Login/>} />
          <Route path="/signup" element={<Signup/>} />
          <Route path="/cart" 
                  element={  <ProectedPageRoute>
                                <Cart />
                            </ProectedPageRoute>  } />
          <Route path="/products/:pid" element={<ProductDetail />} />
          <Route path="/checkout" 
                 element={  <ProectedPageRoute>
                                <CheckoutInfo />
                            </ProectedPageRoute>  } />
          <Route path="/payResult" element={<PayResult />} />
                
          <Route path="/support" element={
            <ProectedPageRoute>
              <Support />
            </ProectedPageRoute>
            } />
        </Route>
      </Routes>
    </BrowserRouter>
    </CartProvider>
    </ProductProvider>
    </AuthProvider>
  );
}







