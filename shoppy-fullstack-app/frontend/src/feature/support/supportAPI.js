import { axiosPost } from '../../utils/dataFetch.js';

export const getList = async(stype) => {
    const url = "/support/list";
    const data = {"stype": stype};
    const jsonData = await axiosPost(url, data);
    return jsonData;
}