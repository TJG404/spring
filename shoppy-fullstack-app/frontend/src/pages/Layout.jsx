import { Outlet } from 'react-router-dom';
import { Header } from '../components/commons/Header.jsx';
import { Footer } from '../components/commons/Footer.jsx';

/**
 * Shoppy-app 사이트의 화면 출력 레이아웃(틀)
 */
export function Layout() {
    return (
        <>
            <Header />
            <Outlet />
            <Footer />
        </>
    );
}