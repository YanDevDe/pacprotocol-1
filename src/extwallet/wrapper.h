// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>
#include <univalue.h>
#include <util.h>
#include <utilstrencodings.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#ifdef WIN32
#include <boost/process/windows.hpp>
#endif

class CProcess
{
public:
    ~CProcess() {
        m_program.clear();
        m_std_out.clear();
        m_std_err.clear();
    }

    void setForExecute(const std::string& prog, const std::vector<std::string>& arg) {
        m_program = prog;
        m_arguments = arg;
    }

    void waitForFinished()
    {
        try {
            boost::asio::io_service svc;
            boost::asio::streambuf out, err;
#ifdef WIN32
            boost::process::child child(m_program, ::boost::process::windows::create_no_window, boost::process::args(m_arguments),
                boost::process::std_out > out, boost::process::std_err > err, svc);
#else
            boost::process::child child(m_program, boost::process::args(m_arguments),
                boost::process::std_out > out, boost::process::std_err > err, svc);
#endif
            svc.run();
            child.wait();
            m_std_out = toString(&out);
            m_std_err = toString(&err);
        } catch (...) {
            m_std_err = "Fail to create process for: " + m_program;
        }
    }

    std::string readAllStandardOutput() {
        return m_std_out;
    }

    std::string readAllStandardError() {
        return m_std_err;
    }

private:
    std::string toString(boost::asio::streambuf* stream)
    {
        std::istream is(stream);
        std::ostringstream os;
        is >> os.rdbuf();
        return os.str();
    }

private:
    std::string m_program;
    std::vector<std::string> m_arguments;
    std::string m_std_out;
    std::string m_std_err;
};

bool execCommand(std::vector<std::string>& params, std::string& response, std::string& error);

