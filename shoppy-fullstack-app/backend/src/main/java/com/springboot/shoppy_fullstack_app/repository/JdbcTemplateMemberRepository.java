package com.springboot.shoppy_fullstack_app.repository;

import com.springboot.shoppy_fullstack_app.dto.Member;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;

@Repository
public class JdbcTemplateMemberRepository  implements  MemberRepository{

    private final JdbcTemplate jdbcTemplate;

    public JdbcTemplateMemberRepository(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public String login(String id) {
        String sql = "select ifnull(MAX(pwd), null) as pwd from member where id = ?";
        String encodePwd = jdbcTemplate.queryForObject(sql, String.class, id);
        return encodePwd;

//        Member member = jdbcTemplate.queryForObject(sql,
//                                    new BeanPropertyRowMapper<>(Member.class),  //RowMapper<T>
//                                    id);
//        return member.getPwd();
    }

    @Override
    public int save(Member member) {
        String sql = "insert into member(id, pwd, name, phone, email, mdate) values(?, ?, ?, ?, ?, now())";
        Object [] param = {
                member.getId(),
                member.getPwd(),
                member.getName(),
                member.getPhone(),
                member.getEmail()
        };
        return jdbcTemplate.update(sql, param);
    }

    @Override
    public Long findById(String id) {
        String sql = "select count(id) from member where id=?";
        Long count = jdbcTemplate.queryForObject(sql, Long.class, id);
        return count;
    }
}
